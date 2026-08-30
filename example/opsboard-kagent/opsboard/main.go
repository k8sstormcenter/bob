package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	if os.Getenv("MODE") == "grpcserver" {
		runGRPCServer()
		return
	}
	rdb := redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "redis:6379")})
	pg, _ := pgxpool.New(context.Background(), env("PG_DSN", "postgres://ops:ops@postgres:5432/ops"))
	go trafficLoop(rdb, pg)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	http.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		rdb.Get(r.Context(), "orders:last")
		if pg != nil {
			pg.Exec(r.Context(), "SELECT 1")
		}
		fmt.Fprintln(w, `{"orders":42}`)
	})
	http.HandleFunc("/api/inventory", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"inventory":"%s"}`+"\n", grpcCheck())
	})
	http.HandleFunc("/api/fx", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get("http://" + env("FX_ADDR", "fx") + "/rate")
		if err == nil {
			resp.Body.Close()
		}
		fmt.Fprintln(w, `{"fx":"EURUSD"}`)
	})
	http.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		publishEvent()
		fmt.Fprintln(w, `{"queued":true}`)
	})
	http.HandleFunc("/api/diag", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			target = "1.1.1.1"
		}
		out, _ := exec.Command("sh", "-c", "dig +short "+target+" ; curl -s -m2 "+target).CombinedOutput()
		w.Write(out)
	})
	http.ListenAndServe(":8080", nil)
}

func trafficLoop(rdb *redis.Client, pg *pgxpool.Pool) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		rdb.Set(ctx, "orders:last", time.Now().Unix(), time.Minute)
		if pg != nil {
			pg.Exec(ctx, "SELECT 1")
		}
		net.LookupHost(env("FX_ADDR", "fx"))
		if resp, err := http.Get("http://" + env("FX_ADDR", "fx") + "/rate"); err == nil {
			resp.Body.Close()
		}
		grpcCheck()
		publishEvent()
		cancel()
		time.Sleep(5 * time.Second)
	}
}

func grpcCheck() string {
	conn, err := grpc.NewClient(env("INVENTORY_ADDR", "inventory:9090"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "down"
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return "down"
	}
	return resp.Status.String()
}

func publishEvent() {
	conn, err := amqp.Dial("amqp://guest:guest@" + env("AMQP_ADDR", "rabbitmq:5672") + "/")
	if err != nil {
		return
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return
	}
	defer ch.Close()
	ch.QueueDeclare("events", false, false, false, false, nil)
	ch.PublishWithContext(context.Background(), "", "events", false, false, amqp.Publishing{Body: []byte("order")})
}

func runGRPCServer() {
	lis, err := net.Listen("tcp", ":9090")
	if err != nil {
		os.Exit(1)
	}
	s := grpc.NewServer()
	hs := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s, hs)
	s.Serve(lis)
}
