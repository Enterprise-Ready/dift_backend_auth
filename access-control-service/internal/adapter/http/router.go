package httpadapter

import (
	"encoding/json"
	app "github.com/diftapp/identity-platform/access-control-service/internal/application/access"
	"github.com/diftapp/identity-platform/access-control-service/internal/platform"
	"github.com/go-chi/chi/v5"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Handler struct{ svc *app.Service }

func NewRouter(svc *app.Service) http.Handler {
	h := &Handler{svc: svc}
	r := chi.NewRouter()
	r.Use(RequestID, Recover, Security)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { platform.JSON(w, 200, map[string]string{"status": "ok"}) })
	r.Route("/v1/users", func(r chi.Router) {
		r.Post("/", h.createUser)
		r.Get("/", h.listUsers)
		r.Get("/{id}", h.getUser)
		r.Post("/{id}/activate", h.activateUser)
		r.Post("/{id}/lock", h.lockUser)
	})
	r.Post("/v1/roles", h.createRole)
	r.Get("/v1/roles", h.listRoles)
	r.Post("/v1/permissions", h.createPermission)
	r.Post("/v1/roles/{roleID}/permissions/{permissionID}", h.grant)
	r.Post("/v1/users/{userID}/roles/{roleID}", h.assign)
	r.Get("/v1/users/{userID}/permissions/{permission}", h.check)
	r.Post("/internal/admin/control", h.adminControl)
	return Timeout(10*time.Second, r)
}
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req app.CreateUserCommand
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		platform.Error(w, 400, "invalid json")
		return
	}
	u, err := h.svc.CreateUser(r.Context(), req)
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 201, u)
}
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	users, err := h.svc.ListUsers(r.Context(), limit, offset)
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 200, users)
}
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := h.svc.GetUser(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		platform.Error(w, 404, err.Error())
		return
	}
	platform.JSON(w, 200, u)
}
func (h *Handler) activateUser(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.ActivateUser(r.Context(), chi.URLParam(r, "id")); err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 200, map[string]string{"status": "activated"})
}
func (h *Handler) lockUser(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.LockUser(r.Context(), chi.URLParam(r, "id")); err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 200, map[string]string{"status": "locked"})
}
func (h *Handler) createRole(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Description string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	role, err := h.svc.CreateRole(r.Context(), req.Name, req.Description)
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 201, role)
}
func (h *Handler) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.svc.ListRoles(r.Context())
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 200, roles)
}
func (h *Handler) createPermission(w http.ResponseWriter, r *http.Request) {
	var req struct{ Key, Resource, Action, Description string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	p, err := h.svc.CreatePermission(r.Context(), req.Key, req.Resource, req.Action, req.Description)
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 201, p)
}
func (h *Handler) grant(w http.ResponseWriter, r *http.Request) {
	err := h.svc.Grant(r.Context(), chi.URLParam(r, "roleID"), chi.URLParam(r, "permissionID"))
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 200, map[string]string{"status": "granted"})
}
func (h *Handler) assign(w http.ResponseWriter, r *http.Request) {
	err := h.svc.AssignRole(r.Context(), chi.URLParam(r, "userID"), chi.URLParam(r, "roleID"), r.URL.Query().Get("tenant_id"))
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 200, map[string]string{"status": "assigned"})
}
func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	d, err := h.svc.Check(r.Context(), chi.URLParam(r, "userID"), r.URL.Query().Get("tenant_id"), chi.URLParam(r, "permission"))
	if err != nil {
		platform.Error(w, 500, err.Error())
		return
	}
	platform.JSON(w, 200, d)
}

func (h *Handler) adminControl(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimSpace(os.Getenv("ADMIN_CONTROL_SHARED_SECRET"))
	if secret != "" && r.Header.Get("X-Admin-Secret") != secret {
		platform.Error(w, 401, "unauthorized")
		return
	}
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		platform.Error(w, 400, "invalid json")
		return
	}
	action, _ := req["action"].(string)
	if strings.TrimSpace(action) == "" {
		platform.Error(w, 400, "action required")
		return
	}
	platform.JSON(w, 202, map[string]any{"accepted": true, "service": "access-control-service", "action": action})
}
