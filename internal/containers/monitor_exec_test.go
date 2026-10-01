package containers

import (
	"context"
	"reflect"
	"testing"
)

func TestPodmanExposesOnlyFixedBoundedMonitorExporter(t *testing.T) {
	podman := reflect.TypeOf(Podman{})
	want := reflect.TypeOf(func(Podman, context.Context, string, []byte) ([]byte, []byte, error) {
		return nil, nil, nil
	})
	method, exists := podman.MethodByName("ExecMonitor")
	if !exists {
		t.Fatal("Podman.ExecMonitor is missing; collector must use the fixed packaged exporter")
	}
	if method.Type != want {
		t.Fatalf("Podman.ExecMonitor has type %s, want %s", method.Type, want)
	}
	value := reflect.ValueOf(Podman{}).MethodByName("ExecMonitor")
	oversized := make([]byte, 64*1024+1)
	result := value.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf("sbx_monitor0001"), reflect.ValueOf(oversized)})
	if len(result) != 3 || result[2].IsNil() || result[0].Len() != 0 || result[1].Len() != 0 {
		t.Fatalf("oversized fixed monitor request result = %#v", result)
	}
}
