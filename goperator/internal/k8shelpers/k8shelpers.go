// Package k8shelpers ports pythonoperator/src/myceliam/k8s_helpers.py: thin
// wrappers around a controller-runtime client.Client for the handful of
// Secret/ServiceAccount/AccessProfile operations every reconciler needs.
//
// Every helper here takes a client.Client explicitly (rather than the
// package-level core_v1()/custom_objects() singletons k8s_helpers.py builds
// lazily) — controller-runtime reconcilers already hold a client.Client
// field, so there's no equivalent lazy-singleton problem to solve.
package k8shelpers

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"myceliam/internal/operr"
)

const apiCallDelay = 15 * time.Second

// ReadAccessProfile reads an AwsAccessProfile/GcpAccessProfile custom object
// into obj (a *v1.AwsAccessProfile or *v1.GcpAccessProfile). Returns
// found=false (not an error) if it doesn't exist.
func ReadAccessProfile(ctx context.Context, c client.Client, namespace, name string, obj client.Object) (found bool, err error) {
	err = c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj)
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, operr.Temporaryf(apiCallDelay, "Error reading %s/%s: %v", namespace, name, err)
}

// ListServiceAccountsByLabel lists ServiceAccounts in namespace matching
// selector — the Go equivalent of a raw Kubernetes label-selector string
// like "k=v" or "k1=v1,k2=v2" (an AND of multiple conditions).
func ListServiceAccountsByLabel(ctx context.Context, c client.Client, namespace string, selector labels.Selector) ([]corev1.ServiceAccount, error) {
	var list corev1.ServiceAccountList
	if err := c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, operr.Temporaryf(apiCallDelay, "Error listing ServiceAccounts in '%s' for selector '%s': %v", namespace, selector, err)
	}
	return list.Items, nil
}

// OwnerReference builds a controller owner reference to sa, the Go
// equivalent of owner_reference(sa_body) in the Python original.
func OwnerReference(sa *corev1.ServiceAccount) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         "v1",
		Kind:               "ServiceAccount",
		Name:               sa.Name,
		UID:                sa.UID,
		Controller:         ptrBool(true),
		BlockOwnerDeletion: ptrBool(false),
	}
}

func ptrBool(b bool) *bool { return &b }

// ReadSecretKeyIfPresent returns the value of key in the named Secret, or
// found=false if the Secret doesn't exist at all (the caller decides what to
// do about that, e.g. generate one).
//
// Returns an *operr.Permanent if the Secret exists but is missing key —
// that's a real misconfiguration, not something to silently paper over.
// Unlike the Python original, no explicit base64-decoding step is needed
// here: corev1.Secret's Data field is already decoded []byte by the time the
// API client unmarshals the response.
func ReadSecretKeyIfPresent(ctx context.Context, c client.Client, namespace, secretName, key string) (value []byte, found bool, err error) {
	var secret corev1.Secret
	err = c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, operr.Temporaryf(apiCallDelay, "Error reading secret '%s/%s': %v", namespace, secretName, err)
	}

	v, ok := secret.Data[key]
	if !ok {
		keys := make([]string, 0, len(secret.Data))
		for k := range secret.Data {
			keys = append(keys, k)
		}
		return nil, false, operr.Permanentf("Secret '%s/%s' exists but has no '%s' key (has: %v)", namespace, secretName, key, keys)
	}
	return v, true, nil
}

// CreateTLSSecretIfAbsent creates a kubernetes.io/tls Secret holding an
// operator-generated keypair.
//
// Only ever called after ReadSecretKeyIfPresent confirmed the secret doesn't
// exist yet, so this never overwrites a pre-existing (e.g. user- or
// cert-manager-provided) secret. A 409 means another reconcile won the race
// to create it first, which is fine — the next reconcile will just read the
// winner's cert.
func CreateTLSSecretIfAbsent(ctx context.Context, c client.Client, namespace, secretName string, certPEM, keyPEM []byte, owner metav1.OwnerReference) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secretName,
			Namespace:       namespace,
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	if err := c.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return operr.Temporaryf(apiCallDelay, "Error creating secret '%s/%s': %v", namespace, secretName, err)
	}
	return nil
}

// WriteCredentialsSecret creates or updates an Opaque Secret with the given
// string data.
func WriteCredentialsSecret(ctx context.Context, c client.Client, namespace, secretName string, data map[string]string, owner metav1.OwnerReference) error {
	byteData := make(map[string][]byte, len(data))
	for k, v := range data {
		byteData[k] = []byte(v)
	}

	var existing corev1.Secret
	err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, &existing)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return operr.Temporaryf(apiCallDelay, "Error reading secret '%s/%s': %v", namespace, secretName, err)
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            secretName,
				Namespace:       namespace,
				OwnerReferences: []metav1.OwnerReference{owner},
			},
			Type: corev1.SecretTypeOpaque,
			Data: byteData,
		}
		if err := c.Create(ctx, secret); err != nil {
			return operr.Temporaryf(apiCallDelay, "Error creating secret '%s/%s': %v", namespace, secretName, err)
		}
		return nil
	}

	existing.OwnerReferences = []metav1.OwnerReference{owner}
	existing.Type = corev1.SecretTypeOpaque
	existing.Data = byteData
	if err := c.Update(ctx, &existing); err != nil {
		return operr.Temporaryf(apiCallDelay, "Error updating secret '%s/%s': %v", namespace, secretName, err)
	}
	return nil
}
