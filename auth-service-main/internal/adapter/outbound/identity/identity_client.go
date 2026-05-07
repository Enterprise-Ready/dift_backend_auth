package integration

import (
	"context"
	"fmt"
	"time"

	repoport "dift_backend_go/auth-service/internal/interface/repository"
	identitypb "dift_backend_go/auth-service/proto/pb/identity"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type IdentityClient struct {
	conn   *grpc.ClientConn
	client identitypb.IdentityServiceClient
}

func NewIdentityClient(grpcAddr string) (*IdentityClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("dial identity grpc failed: %w", err)
	}

	return &IdentityClient{
		conn:   conn,
		client: identitypb.NewIdentityServiceClient(conn),
	}, nil
}

func (g *IdentityClient) Close() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

func (g *IdentityClient) GetUserByEmail(ctx context.Context, email string) (*repoport.IdentityUser, error) {
	res, err := g.client.GetUserByEmail(ctx, &identitypb.GetUserByEmailRequest{Email: email})
	if err != nil {
		return nil, err
	}
	if res.GetId() == "" {
		return nil, nil
	}
	return &repoport.IdentityUser{
		ID:       res.GetId(),
		Name:     res.GetName(),
		Email:    res.GetEmail(),
		Phone:    res.GetPhone(),
		Password: res.GetPassword(),
	}, nil
}

func (g *IdentityClient) CreateEmailUser(ctx context.Context, name, email, password string) (*repoport.IdentityUser, error) {
	res, err := g.client.CreateEmailUser(ctx, &identitypb.CreateEmailUserRequest{
		Name:     name,
		Email:    email,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	return &repoport.IdentityUser{
		ID:       res.GetId(),
		Name:     res.GetName(),
		Email:    res.GetEmail(),
		Phone:    res.GetPhone(),
		Password: res.GetPassword(),
	}, nil
}

func (g *IdentityClient) GetUserRoles(ctx context.Context, userID string) ([]repoport.IdentityRole, error) {
	res, err := g.client.GetUserRoles(ctx, &identitypb.GetUserRolesRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	out := make([]repoport.IdentityRole, 0, len(res.GetRoles()))
	for _, r := range res.GetRoles() {
		out = append(out, repoport.IdentityRole{Name: r.GetName()})
	}
	return out, nil
}

func (g *IdentityClient) Health(ctx context.Context) error {
	_, err := g.client.Health(ctx, &identitypb.HealthRequest{})
	return err
}
