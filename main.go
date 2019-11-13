package main

import (
	"log"
	"path/filepath"

	"github.com/hoisie/web"
	"github.com/shiqinfeng1/lite-ethereum/crypto"
	"github.com/shiqinfeng1/lite-ethereum/p2p"
	"github.com/shiqinfeng1/lite-ethereum/p2p/nat"
	"github.com/shiqinfeng1/lite-ethereum/v1"
)

const (
	datadir                = "./lite-geth-db/"
	datadirPrivateKey      = "nodekey"            // Path within the datadir to the node's private key
	datadirDefaultKeyStore = "keystore"           // Path within the datadir to the keystore
	datadirStaticNodes     = "static-nodes.json"  // Path within the datadir to the static node list
	datadirTrustedNodes    = "trusted-nodes.json" // Path within the datadir to the trusted node list
	datadirNodeDatabase    = "nodes"              // Path within the datadir to store the node infos
)

var MainnetBootnodes = []string{
	"enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@52.16.188.185:30303", // IE
	"enode://3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99@13.93.211.84:30303",  // US-WEST
	"enode://78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d@191.235.84.50:30303", // BR
	"enode://158f8aab45f6d19c6cbf4a089c2670541a8da11978a2f90dbf6a502a4a3bab80d288afdbeb7ec0ef6d92de563767f3b1ea9e8e334ca711e9f8e2df5a0385e8e6@13.75.154.138:30303", // AU
	"enode://1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082@52.74.57.123:30303",  // SG

}
var RinkebyBootnodes = []string{
	"enode://a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf@52.169.42.101:30303", // IE
	"enode://343149e4feefa15d882d9fe4ac7d88f885bd05ebb735e547f12e12080a9fa07c8014ca6fd7f373123488102fe5e34111f8509cf0b7de3f5b44339c9f25e87cb8@52.3.158.184:30303",  // INFURA
	"enode://b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6@159.89.28.211:30303", // AKASHA
}

func main() {
	log.Println("1.1 生成节点私钥... 创建levelDB...")
	privateKey, _ := crypto.GenerateKey()
	nodeDataBase, _ := filepath.Abs(filepath.Join(datadir, datadirNodeDatabase))
	log.Println("DB Path: ", nodeDataBase)

	serverConfig := p2p.Config{
		Name:         "lite-geth",
		PrivateKey:   privateKey,
		NodeDatabase: nodeDataBase,
		ListenAddr:   ":30308",
		MaxPeers:     50,
		NAT:          nat.Any(),
	}
	log.Printf("1.2 p2p server 的配置是: %+v", serverConfig)
	p2p.NewServer(serverConfig, RinkebyBootnodes)

	log.Printf("1.3 启动rpc服务... ")
	web.Post("/", v1.Route)
	web.Match("OPTIONS", "/", func(ctx *web.Context) string {
		ctx.SetHeader("Access-Control-Allow-Origin", "*", true)
		ctx.SetHeader("Access-Control-Allow-Method", "POST", true)
		ctx.SetHeader("Access-Control-Allow-Headers", "accept,content-type,cookieorigin", true)
		ctx.SetHeader("Access-Control-Allow-Credentials", "true", true)
		return ""
	})
	web.Run(":8848")
}
