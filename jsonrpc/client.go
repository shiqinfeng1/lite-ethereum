package main

import (
	"fmt"
	"log"

	jsonrpcClient "github.com/ybbus/jsonrpc"
)

func dumpDiscoverTable() {
	rpcClient := jsonrpcClient.NewClient("http://localhost:8848")
	response, err := rpcClient.Call("dump_discovertable")

	switch e := err.(type) {
	case nil: // if error is nil, do nothing
	case *jsonrpcClient.HTTPError:
		log.Println("Occur an Error:", e.Code)
		return
	default:
		log.Printf("Occur Unkown Error: %v", e)
		return
	}
	log.Printf("Got Result: %+v", response)
	// no error, go on...
}

func main() {
	var index string
	fmt.Println("请求列表:")
	fmt.Println("1. 打印发现表. dumpDiscoverTable")
	fmt.Println("")
	fmt.Printf("请输入请求编号:")
	fmt.Scanln(&index)
	switch index {
	case "1":
		dumpDiscoverTable()
	}
}
