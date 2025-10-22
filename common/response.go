package common

import (
	"encoding/json"
	"net/http"
)

// Response 统一响应结构
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// SuccessResponse 成功响应
func SuccessResponse(data interface{}) Response {
	return Response{
		Code:    200,
		Message: "success",
		Data:    data,
	}
}

// ErrorResponse 错误响应
func ErrorResponse(code int, message string) Response {
	return Response{
		Code:    code,
		Message: message,
	}
}

// RespondJSON 返回JSON响应
func RespondJSON(w http.ResponseWriter, statusCode int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// RespondSuccess 返回成功响应
func RespondSuccess(w http.ResponseWriter, data interface{}) {
	RespondJSON(w, http.StatusOK, SuccessResponse(data))
}

// RespondError 返回错误响应
func RespondError(w http.ResponseWriter, statusCode int, message string) {
	RespondJSON(w, statusCode, ErrorResponse(statusCode, message))
}

// RespondBadRequest 返回400错误
func RespondBadRequest(w http.ResponseWriter, message string) {
	RespondError(w, http.StatusBadRequest, message)
}

// RespondNotFound 返回404错误
func RespondNotFound(w http.ResponseWriter, message string) {
	RespondError(w, http.StatusNotFound, message)
}

// RespondInternalError 返回500错误
func RespondInternalError(w http.ResponseWriter, message string) {
	RespondError(w, http.StatusInternalServerError, message)
}

// RespondMethodNotAllowed 返回405错误
func RespondMethodNotAllowed(w http.ResponseWriter, message string) {
	RespondError(w, http.StatusMethodNotAllowed, message)
}
