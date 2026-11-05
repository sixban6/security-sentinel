package main

import (
	"flag"
	"log"
	"os"

	"github.com/sixban6/security-sentinel/internal/app/gui"
)

func main() {
	cfgPath := flag.String("config", "", "配置文件路径 (默认自动查找 sentinel.yaml)")
	openWindow := flag.Bool("window", false, "启动时直接打开全景安全指挥台主窗口")
	writeIcon := flag.String("write-icon", "", "生成 1024x1024 应用图标 PNG 到指定路径并退出")
	flag.Parse()

	if *writeIcon != "" {
		if err := os.WriteFile(*writeIcon, gui.RenderAppBundleIconPNG(1024), 0o644); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := gui.RunDesktopApp(*cfgPath, *openWindow); err != nil {
		log.Fatal(err)
	}
}
