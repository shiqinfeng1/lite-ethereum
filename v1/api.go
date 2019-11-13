package v1

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/hoisie/web"
	"github.com/shiqinfeng1/lite-ethereum/p2p"
)

const (
	_ int = 1000 + iota
	ERRCODE_HolderBalance1
	ERRCODE_HolderBalance2
	ERRCODE_HolderBalance3
	ERRCODE_HolderBalance4
	ERRCODE_HolderBalance5

	ERRCODE_Handle
	ERRCODE_Route
)

// ErrorReturns 发生错误的时候的返回值封装
func ErrorReturns(id, errcode int, errmsg string) *JSONRPCResponse {
	returns := &JSONRPCResponse{
		ID:      id,
		Jsonrpc: "2.0",
		Result:  ReturnBodyNoPage{ErrCode: errcode, ErrMsg: errmsg},
	}
	return returns
}

// ResultNoPageReturns 返回值封装
func ResultNoPageReturns(id int, data interface{}) *JSONRPCResponse {
	returns := &JSONRPCResponse{
		ID:      id,
		Jsonrpc: "2.0",
		Result:  ReturnBodyNoPage{ErrCode: 0, ErrMsg: "", Data: data},
	}
	return returns
}

// ResultWithPageReturns 返回值封装
func ResultWithPageReturns(id int, data interface{}, page PageBody) *JSONRPCResponse {
	returns := &JSONRPCResponse{
		ID:      id,
		Jsonrpc: "2.0",
		Result: ReturnBodyWithPage{
			ErrCode: 0, ErrMsg: "",
			Data: data,
			Page: page,
		},
	}
	return returns
}
func praseRequest(ctx *web.Context) (*JSONRPCRequest, error) {
	var req = JSONRPCRequest{}
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		return &JSONRPCRequest{}, err
	}
	if req.Jsonrpc != "2.0" {
		return &JSONRPCRequest{}, fmt.Errorf("JSONRPC Request Version Mismatch: %v", req.Jsonrpc)
	}
	return &req, nil
}

func dumpDiscoverTable(id int, params string) *JSONRPCResponse {

	if p2p.Running == nil {
		return ResultNoPageReturns(id, "not ready")
	}
	buckets := p2p.Running.DumpDiscoverTable()
	return ResultNoPageReturns(id, buckets)
}

//Handle 分发
func Handle(ctx *web.Context, req *JSONRPCRequest) *JSONRPCResponse {

	switch req.Method {
	case "dump_discovertable": //
		return dumpDiscoverTable(req.ID, req.Params)
	}
	return ErrorReturns(req.ID, ERRCODE_Handle, "Unkown Method: "+req.Method)
}

//Route Route
func Route(ctx *web.Context) string {

	ctx.ContentType("json")
	ctx.SetHeader("Access-Control-Allow-Origin", "*", true)
	req, err := praseRequest(ctx)
	if err != nil {
		log.Println("praseRequest Fial: ", err.Error())
		data, _ := json.Marshal(ErrorReturns(req.ID, ERRCODE_Route, "Unkown Request Body"))
		return string(data)
	}
	bs, _ := json.MarshalIndent(req, "", "    ")
	log.Println("RPC Req Data: ", string(bs))

	data, _ := json.MarshalIndent(Handle(ctx, req), "", "    ")
	return string(data)

}
