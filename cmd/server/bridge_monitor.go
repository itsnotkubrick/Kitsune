package main

import (
	"context"
	"fmt"
	"time"

	"kitsune/internal/bridge"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/events"
)

// bridgeMonitor раз в минуту проверяет узлы-мосты с сервера: TCP-порты, которые через них пересылаются. Упавший узел (три проверки подряд
// без ответа) вызывает уведомление, а при включённом «автоскрытии» его копии пропадают из подписок, пока он не вернётся.
func bridgeMonitor() {
	time.Sleep(45 * time.Second)
	for {
		runBridgeChecks()
		time.Sleep(time.Minute)
	}
}

func runBridgeChecks() {
	nodes := bridge.List()
	bridge.PruneStatuses(nodes)
	if len(nodes) == 0 {
		return
	}
	inbounds, _ := db.GetInbounds()
	env := core.PublicEnv()
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		fw := bridge.Forwards(n.Select(inbounds), env)
		var known, ok bool
		var ms int64
		var results []bridge.PortStatus
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if addr, err := bridge.ResolveHostContext(ctx, n.Host); err == nil {
			results = bridge.ProbePorts(ctx, addr, fw)
			for _, r := range results {
				if r.Proto == "tcp" {
					known = true
					if r.OK {
						if !ok || r.Ms < ms {
							ms = r.Ms
						}
						ok = true
					}
				}
			}
		} else {
			for _, f := range fw {
				results = append(results, bridge.PortStatus{Proto: f.Proto, Port: f.Port, Error: "dns", Note: "Имя узла не разрешается"})
			}
			// имя не разрешается: для узла с TCP-портами это отказ
			for _, f := range fw {
				if f.Proto == "tcp" {
					known = true
				}
			}
		}
		cancel()
		st, changed := bridge.ObserveNode(n, known, ok, ms, time.Now(), results)
		if !changed {
			continue
		}
		switch st.State {
		case "down":
			hide := ""
			if n.AutoHide {
				hide = ": его TCP-копии убраны из подписок, пока он не вернётся"
			}
			events.Notify("bridge_down", n.ID, fmt.Sprintf("узел-мост «%s» (%s) не отвечает по TCP%s", n.Name, n.Host, hide), 30*time.Minute)
		case "ok":
			events.Reset("bridge_down", n.ID)
			events.Audit("система", "Узел-мост снова отвечает", n.Name+" ("+n.Host+")")
		}
	}
}

// bridgeStatuses – состояния узлов для интерфейса.
func bridgeStatuses() map[string]bridge.Status {
	out := map[string]bridge.Status{}
	for _, n := range bridge.List() {
		out[n.ID] = bridge.StatusOfNode(n)
	}
	return out
}
