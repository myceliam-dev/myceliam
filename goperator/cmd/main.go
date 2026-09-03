// Command myceliam-operator is the Go port of pythonoperator's kopf
// entrypoint (`kopf run --standalone --all-namespaces -m myceliam.handlers`):
// a single-instance (no leader election, matching --standalone) operator
// watching every namespace in the cluster.
package main

import (
	"context"
	"flag"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	myceliamv1 "myceliam/api/v1"
	"myceliam/internal/config"
	"myceliam/internal/controller"
	"myceliam/internal/oidc"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(myceliamv1.AddToScheme(scheme))
}

// setupable is satisfied by every reconciler type in the controller package.
type setupable interface {
	SetupWithManager(ctrl.Manager) error
}

func main() {
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)

	settings, err := config.Load()
	if err != nil {
		logger.Error(err, "invalid configuration")
		os.Exit(1)
	}

	ctx := context.Background()
	restConfig := ctrl.GetConfigOrDie()

	// A direct (uncached) client, usable immediately — the manager's own
	// client isn't ready until its cache starts, but GetProvider needs to
	// read the operator's own credential Secret (see keycloak.NewProvider's
	// AdminSecretName/AdminKeypairSecretName) before the manager exists.
	bootstrapClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		logger.Error(err, "unable to build bootstrap client")
		os.Exit(1)
	}

	// Built once at startup, same as kopf's @kopf.on.startup handler building
	// memo.oidc — a nil oidcProvider (settings.OidcProvider == "none") is a
	// valid, deliberate configuration for spiffe-only deployments, not an error.
	oidcProvider, err := oidc.GetProvider(ctx, settings, bootstrapClient)
	if err != nil {
		logger.Error(err, "failed to build OIDC provider")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{Scheme: scheme})
	if err != nil {
		logger.Error(err, "unable to start manager")
		os.Exit(1)
	}

	deps := &controller.Deps{
		Client:   mgr.GetClient(),
		Settings: settings,
		OIDC:     oidcProvider,
	}

	reconcilers := []setupable{
		&controller.ServiceAccountReconciler{Deps: deps},
		&controller.NamespaceReconciler{Deps: deps},
		&controller.AwsAccessProfileReconciler{Deps: deps},
		&controller.GcpAccessProfileReconciler{Deps: deps},
		&controller.SecretReconciler{Deps: deps},
		&controller.AutoidpAllowlistReconciler{Deps: deps},
	}
	for _, r := range reconcilers {
		if err := r.SetupWithManager(mgr); err != nil {
			logger.Error(err, "unable to set up reconciler")
			os.Exit(1)
		}
	}

	logger.Info("starting myceliam operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "manager exited with error")
		os.Exit(1)
	}
}
