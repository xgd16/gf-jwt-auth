package jwtAuth

import (
	"context"
	jwt "github.com/gogf/gf-jwt/v2"
	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/crypto/gmd5"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
	jwtV4 "github.com/golang-jwt/jwt/v4"
	"time"
)

// GetIdentity 获取身份主键
func GetIdentity(ctx context.Context) *g.Var {
	return Auth().GetIdentity(ctx).(*g.Var)
}

// GetLoginData 获取登录数据
func GetLoginData(ctx context.Context) map[string]*gvar.Var {
	return gvar.New(jwt.ExtractClaims(ctx), true).MapStrVar()
}

// ParseTokenData 解析token的数据
func ParseTokenData(token string) (*jwtV4.Token, error) {
	return jwtV4.Parse(token, func(token *jwtV4.Token) (interface{}, error) {
		return Auth().Key, nil
	})
}

// OfflineToken 将token失效
func OfflineToken(token string) error {
	// 解析Token数据
	tokenData, err := ParseTokenData(token)

	if err != nil {
		return err
	}
	// 转换为map数据
	claims := jwt.ExtractClaimsFromToken(tokenData)

	exp := int64(claims["exp"].(float64))

	auth := Auth()

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
