package jwtAuth

import (
	"context"
	"errors"
	jwt "github.com/gogf/gf-jwt/v2"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcache"
	"github.com/gogf/gf/v2/os/gctx"
	"time"
)

var authService *jwt.GfJWTMiddleware

type GetUserHandle func(r *ghttp.Request) map[string]any
type AuthenticatorCallbackHandle func(r *ghttp.Request) error

var getUserFunc GetUserHandle
var authenticatorCallback AuthenticatorCallbackHandle = nil

// SetGetUserFunc 设置获取用函数
func SetGetUserFunc(userFunc GetUserHandle) {
	getUserFunc = userFunc
}

// SetAuthenticatorEvent 设置验证登录事件需要执行的内容
func SetAuthenticatorEvent(fn AuthenticatorCallbackHandle) {
	authenticatorCallback = fn
}

func Auth() *jwt.GfJWTMiddleware {
	return authService
}

func init() {
	ctx := gctx.New()

	jwtKey, err := g.Cfg().Get(ctx, "jwt.key")
	realm, err := g.Cfg().Get(ctx, "jwt.realm")
	timeOut, err := g.Cfg().Get(ctx, "jwt.timeOut")
	maxRefresh, err := g.Cfg().Get(ctx, "jwt.maxRefresh")

	if err != nil || jwtKey.IsEmpty() {
		panic("读取 JWT 数据失败")
	}

	auth := jwt.New(&jwt.GfJWTMiddleware{
		Realm:           realm.String(),
		Key:             jwtKey.Bytes(),
		Timeout:         time.Second * 86400 * timeOut.Duration(),
		MaxRefresh:      time.Second * 86400 * maxRefresh.Duration(),
		IdentityKey:     "id",
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,
		Authenticator:   Authenticator,
		Unauthorized:    Unauthorized,
		PayloadFunc:     PayloadFunc,
		IdentityHandler: IdentityHandler,
		CacheAdapter:    gcache.NewAdapterRedis(g.Redis()),
	})

	authService = auth
}

// PayloadFunc 是一个回调函数，会在登录时调用。
// 使用此函数可以向 webtoken 添加额外的有效负载数据。
// 然后通过 c.Get("JWT_PAYLOAD") 在请求期间提供数据。
// 注意payload没有加密。
// jwt.io上提到的属性不能作为map的key。
// 可选，默认情况下不会设置额外的数据。
func PayloadFunc(data interface{}) jwt.MapClaims {
	claims := jwt.MapClaims{}
	params := data.(map[string]interface{})
	if len(params) > 0 {
		for k, v := range params {
			claims[k] = v
		}
	}
	return claims
}

// IdentityHandler 从 JWT 获取身份并为每个请求设置身份
// 使用这个函数，通过 r.GetParam("id") 获取身份
func IdentityHandler(ctx context.Context) interface{} {
	claims := jwt.ExtractClaims(ctx)
	return claims[authService.IdentityKey]
}

// Unauthorized 用于定义自定义的 Unauthorized 回调函数。
func Unauthorized(ctx context.Context, code int, message string) {
	r := g.RequestFromCtx(ctx)

	switch message {
	case "Token is expired", "signature is invalid":
		message = "登录已过期请重新登录"
	case "cookie token is empty":
		message = "没有找到 Token"
	case "token is invalid":
		message = "无效的 Token"
	}

	r.Response.Status = code

	r.Response.WriteJson(g.Map{
		"code": 1001,
		"msg":  message,
	})

	r.ExitAll()
}

// Authenticator 用于验证登录参数。
// 它必须返回用户数据作为用户标识符，它将存储在Claim Array中。
// 如果你的 identityKey 是 'id'，你的用户数据必须有 'id'
// 检查错误 (e) 以确定适当的错误消息。
func Authenticator(ctx context.Context) (any, error) {
	r := g.RequestFromCtx(ctx)

	if user := getUserFunc(r); user != nil {
		return user, nil
	}

	if authenticatorCallback != nil {
		if err := authenticatorCallback(r); err != nil {
			return nil, err
		}
	}

	return nil, errors.New("无效的登录凭证")
}
