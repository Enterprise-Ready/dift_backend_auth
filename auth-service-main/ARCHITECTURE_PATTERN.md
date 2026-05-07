# Auth Service Architecture Pattern

Pattern เดียวกับ travel/user-coupon service:

- `cmd/main.go` = entrypoint บาง ๆ
- `internal/app` = bootstrap/wiring ทั้งหมด
- `internal/adapter/inbound` = HTTP/gRPC/Event inbound adapter
- `internal/adapter/outbound` = outbound adapter เช่น identity gateway
- `internal/integration` = infra/server/client ที่ไม่ผูก business
- `internal/service` = business/service logic เดิม
- `internal/interface` = port/interface เดิม
- `pkg/*` = engine/direct package ที่ปรับให้เข้ากับ auth service เช่น metrics, retry, health, authengine
- middleware ใช้ import จาก `github.com/PlatformCore/libpackage/middleware/...` ผ่าน inbound middleware layer ไม่สร้าง wrapper ซ้ำใน service

Legacy auth engine V2 ถูกเก็บไว้ที่ `docs/legacy-auth-engine-v2` พร้อม build tag `legacy` เพื่อกันชน build หลัก
และ logic สำคัญถูกสรุปเป็น `pkg/authengine` สำหรับ session/revocation engine.
