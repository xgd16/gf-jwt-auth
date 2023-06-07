# 用于GO GF框架的 JWT AUTH 解耦
### 使用 [gf-jwt](http://github.com/gogf/gf-jwt)

#### 第一步
```go
package middleware

import (
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"gogs.mirlowz.com/x/gf-jwt-auth/jwtAuth"
	"gogs.mirlowz.com/x/gf-x-tool/xTool"
	"sdt-service/models"
	"sdt-service/service/webService/respCode"
	"sdt-service/types"
)

type ClientAdminUserAuthMiddleware struct {
	jwt *jwtAuth.JwtAuth
}

func ClientAdminUserAuth(jwt *jwtAuth.JwtAuth) *ClientAdminUserAuthMiddleware {
	// getClientAdminUser 为登陆时 调用 主要作用为 获取存储到 token 的数据
	return &ClientAdminUserAuthMiddleware{
		jwt: jwt.SetGetUserFunc(getClientAdminUser).Create(),
	}
}

func (s *ClientAdminUserAuthMiddleware) CORS(r *ghttp.Request) {
	r.Response.CORSDefault()
	r.Middleware.Next()
}

func (s *ClientAdminUserAuthMiddleware) Auth(r *ghttp.Request) {
	s.jwt.GetAuth().MiddlewareFunc()(r)

	r.Middleware.Next()
}
// 登陆时调用
func getClientAdminUser(r *ghttp.Request) map[string]any {
	return g.Map{
		"username": "a",
    }
}
```
#### 第二步
```go
admin := middleware.ClientAdminUserAuth(jwtAuth.New("clientAdmin"))
// 中间键注册到路由
group.Middleware(
	admin.CORS,
	admin.Auth,
	ghttp.MiddlewareHandlerResponse,
)
```