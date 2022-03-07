package main

import (
	"context"
	"fmt"
	"log"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	"knative.dev/pkg/injection"
	"knative.dev/pkg/signals"
)

func main() {
	ctx, _ := injection.EnableInjectionOrDie(signals.NewContext(), nil)

	kc := kubeclient.Get(ctx)

	p, err := cloudevents.NewHTTP()
	if err != nil {
		log.Fatalln("failed to create protocol:", err.Error())
	}

	c, err := cloudevents.NewClient(p)
	if err != nil {
		log.Fatalln("failed to create client,", err)
	}

	log.Println("will listen on :8080")
	if err := c.StartReceiver(ctx, func(ctx context.Context, event cloudevents.Event) {
		if event.Source() == "falco.org" && event.Type() == "falco.rule.output.v1" {
			payload := &FalcoPayload{}
			if err := event.DataAs(payload); err != nil {
				log.Println("failed to parse falco payload from event:", err)
				return
			}

			if payload.Rule == "Outbound Connection to C2 Servers" {
				labelkey := "falco-event"
				labelValue := "c2-server-detected"
				if _, err := AddLabelPod(labelkey, labelValue, kc, payload.Fields.Namespace, ctx, payload.Fields.Pod); err != nil {
					log.Println("failed to label pod from event:", err)
					return
				}
				log.Printf("[%s] labeled %s from %s because %s\n", payload.Rule, payload.Fields.Pod, payload.Fields.Namespace, payload.Output)
			}
		} else {
			log.Println("ignoring event:\n", event)
		}
	}); err != nil {
		log.Fatal("failed to start receiver:", err)
	}
}

func AddLabelPod(labelkey string, labelValue string, kc kubernetes.Interface, namespace string, ctx context.Context, podname string) (result *v1.Pod, err error) {
	labelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"%s" }]`, labelkey, labelValue)
	return kc.CoreV1().Pods(namespace).Patch(ctx, podname, types.JSONPatchType, []byte(labelPatch), metav1.PatchOptions{})
}

// FalcoPayload is a struct to map falco event json
type FalcoPayload struct {
	Output   string    `json:"output"`
	Priority string    `json:"priority"`
	Rule     string    `json:"rule"`
	Time     time.Time `json:"time"`
	Fields   struct {
		ContainerId        string `json:"container.id"`
		ContainerImageRepo string `json:"container.image.repository"`
		Namespace          string `json:"k8s.ns.name"`
		Pod                string `json:"k8s.pod.name"`
		ProcCmd            string `json:"proc.cmdline"`
		ProcName           string `json:"proc.name"`
		ProcPName          string `json:"proc.pname"`
		ProcTTY            int64  `json:"proc.tty"`
		UserLoginUID       int64  `json:"user.loginuid"`
		UserName           string `json:"user.name"`
	} `json:"output_fields"`
}
