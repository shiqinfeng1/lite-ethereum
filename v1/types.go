package v1

//JSONRPCRequest "jsonrpc":"2.0","method":"`+method+`","params":`+params+`,"id":1}
type JSONRPCRequest struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  string `json:"params"`
	ID      int    `json:"id"`
}

//BlcokResult BlcokResult
type JSONRPCResponse struct {
	ID      int         `json:"id"`
	Jsonrpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
}

// type TokenListParams struct {
// 	Token string     `json:"token"`
// 	Page  PageParams `json:"page"`
// }

// PageParams 分页参数
type PageParams struct {
	CurrentPage int `json:"current_page"` //当前获取第几页 编号从0开始
	PerPage     int `json:"per_page"`     //每页包含几条记录
}

// PageBody 分页结果
type PageBody struct {
	CurrentPage int `json:"current_page"`       //当前返回第几页
	PerPage     int `json:"per_page,omitempty"` //每页包含几条记录，默认和输入相同，最大值100条
	Total       int `json:"total,omitempty"`    //总共几条记录
}
type ReturnBodyWithPage struct {
	ErrCode int         `json:"errcode"`
	ErrMsg  string      `json:"errmsg"`
	Data    interface{} `json:"data"`
	Page    PageBody    `json:"page"`
}

// ReturnBodyNoPage 返回值封装
type ReturnBodyNoPage struct {
	ErrCode int         `json:"errcode"`
	ErrMsg  string      `json:"errmsg"`
	Data    interface{} `json:"data"`
}
