package controller

import (
	"go-rest-api/model"
	"go-rest-api/usecase"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
)

type IUserController interface {
	SignUp(c echo.Context) error
	Login(c echo.Context) error
	LogOut(c echo.Context) error
}

type userController struct {
	uu usecase.IUserUsecase
}

func NewUserController(uu usecase.IUserUsecase) IUserController {
	return &userController{uu}
}

func (uc *userController) SignUp(c echo.Context) error {
	user := model.User{}
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}
	userRes, err := uc.uu.SignUp(user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusCreated, userRes)
}

func (uc *userController) Login(c echo.Context) error {
	user := model.User{}
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}
	tokenString, err := uc.uu.Login(user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	// CookieにJWTをセットする
	cookie := new(http.Cookie)                      // Cookie構造体のポインタを生成
	cookie.Name = "token"                           // Cookieの名前
	cookie.Value = tokenString                      // Cookieに保存する値
	cookie.Expires = time.Now().Add(24 * time.Hour) // Cookieの有効期限
	cookie.Path = "/"                               // Cookieを保存するパス
	cookie.Domain = os.Getenv("API_DOMAIN")
	// cookie.Secure = true // HTTPSでのみCookieを送信する
	cookie.HttpOnly = true                  // JavaScriptからCookieにアクセスできないようにする
	cookie.SameSite = http.SameSiteNoneMode // SameSite属性をNoneに設定する
	c.SetCookie(cookie)
	return c.NoContent(http.StatusOK)
}

func (uc *userController) LogOut(c echo.Context) error {
	cookie := new(http.Cookie)
	cookie.Name = "token"
	cookie.Value = ""
	cookie.Expires = time.Now()
	cookie.Path = "/" // Cookieを保存するパス
	cookie.Domain = os.Getenv("API_DOMAIN")
	// cookie.Secure = true // HTTPSでのみCookieを送信する
	cookie.HttpOnly = true                  // JavaScriptからCookieにアクセスできないようにする
	cookie.SameSite = http.SameSiteNoneMode // SameSite属性をNoneに設定する
	c.SetCookie(cookie)
	return c.NoContent(http.StatusOK)
}
