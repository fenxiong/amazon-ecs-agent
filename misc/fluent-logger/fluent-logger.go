package fluent_logger

import (
"fmt"
"github.com/fluent/fluent-logger-golang/fluent"
"log"
"os"
"strconv"
"time"
)

func main() {
	port, _ := strconv.ParseInt(os.Getenv("FLUENT_PORT"), 10, 32)
	logger, err := fluent.New(fluent.Config{FluentPort: int(port), FluentHost: os.Getenv("FLUENT_HOST")})
	if err != nil {
		fmt.Println(err)
	}
	defer logger.Close()
	tag := "logsender-firelens"
	var data = map[string]string{
		"foo":    "bar",
		"hoge":   "hoge",
		"Hello":  "HIi",
		"yellow": "blue",
		"green":  "pink"}
	for i := 0; i < 100; i++ {
		e := logger.Post(tag, data)
		if e != nil {
			log.Println("Error while posting log: ", e)
		} else {
			log.Println("Success to post log")
		}
		time.Sleep(1000 * time.Millisecond)
	}
}