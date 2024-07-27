package routes

import (
	"golang/src/controllers"
	"golang/src/middlewares"

	"github.com/gin-gonic/gin"
)

func startupsGroupRouter(baseRouter *gin.RouterGroup) {
	startups := baseRouter.Group("/auth")

	startups.POST("/login", controllers.Login)
	startups.POST("/register", controllers.Register)
}

func SetupRoutes() *gin.Engine {
	r := gin.Default()

	versionRouter := r.Group("/api")

	startupsGroupRouter(versionRouter)
	versionRouter.GET("/users",
		middlewares.AuthMiddleware(), controllers.GetUsers)
	return r
}
