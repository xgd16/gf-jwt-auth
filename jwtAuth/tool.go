package jwtAuth

import (
	"context"
	jwt "github.com/gogf/gf-jwt/v2"
	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gcache"
	jwtV4 "github.com/golang-jwt/jwt/v4"
	"time"
)

// UserCtxKey 用户 ctx key
const UserCtxKey = "userInfo"

// GetIdFromCtx 通过 ctx 获取 id
func GetIdFromCtx(r *ghttp.Request) int {
	if m, ok := r.GetCtxVar(UserCtxKey).MapStrVar()["id"]; ok {
		return m.Int()
	}
	panic("获取不到登陆 id")
}

// GetDataFromCtx 通过 ctx 获取登陆 数据
func GetDataFromCtx[T any](r *ghttp.Request) (data *T, err error) {
	data = new(T)
	err = r.GetCtxVar(UserCtxKey).Scan(data)
	if err != nil {
		return
	}
	return
}

// GetIdentity 获取身份主键
func GetIdentity(ctx context.Context, jwtName string) *g.Var {
	return JwtDataMap[jwtName].GetAuth().GetIdentity(ctx).(*g.Var)
}

// GetLoginData 获取登录数据
func GetLoginData(ctx context.Context) map[string]*gvar.Var {
	return gvar.New(jwt.ExtractClaims(ctx), true).MapStrVar()
}

// ParseTokenData 解析token的数据
func ParseTokenData(token string, jwtName string) (*jwtV4.Token, error) {
	return jwtV4.Parse(token, func(token *jwtV4.Token) (interface{}, error) {
		return JwtDataMap[jwtName].GetAuth().Key, nil
	})
}

// OfflineToken 将token失效
func OfflineToken(token string, jwtName string) error {
	// 解析Token数据
	tokenData, err := ParseTokenData(token, jwtName)

	if err != nil {
		return err
	}
	// 转换为map数据
	claims := jwt.ExtractClaimsFromToken(tokenData)

	exp := int64(claims["exp"].(float64))

	auth := JwtDataMap[jwtName].GetAuth()

	// save duration time = (exp + max_refresh) - now
	duration := time.Unix(exp, 0).Add(auth.MaxRefresh).Sub(auth.TimeFunc()).Truncate(time.Second)
	// token转换为key值
	token, err = gmd5.EncryptString(token)

	if err != nil {
		return err
	}
	// 写入到缓存
	cache := gcache.New()

	cache.SetAdapter(gcache.NewAdapterRedis(g.Redis()))

	if cache.Set(context.Background(), token, true, duration) != nil {
		return err
	}

	return nil
}
