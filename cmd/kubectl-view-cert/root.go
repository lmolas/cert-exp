package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/lmolas/kubectl-view-cert/internal/parse"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // combined authprovider import
	"k8s.io/klog"
)

const (
	allNamespacesFlag      = "all-namespaces"
	expiredFlag            = "expired"
	showCaCertFlag         = "show-ca"
	expiredDaysFromNowFlag = "expired-days-from-now"
)

var cf *genericclioptions.ConfigFlags

// This variable is populated by goreleaser
var version string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:          "kubectl view-cert [flags] [secret-name [secret-key]]",
	SilenceUsage: true, // for when RunE returns an error
	Short:        "View certificate information stored in secrets",
	Example: "# List certificates from secrets in current namespace \n" +
		"kubectl view-cert \n" +
		"\n" +
		"# List certificates from secrets in all namespaces \n" +
		"kubectl view-cert -A \n" +
		"\n" +
		"# List expired certificates from secrets in all namespaces \n" +
		"kubectl view-cert -A -E \n" +
		"\n" +
		"# List certificates that will expire in 90 days in all namespaces \n" +
		"kubectl view-cert -A -D 90 \n" +
		"\n" +
		"# If you want to include CA certificate informations you can use -S flag \n" +
		"\n" +
		"# View certificate from a specific secret (secret is parsed only if its type is kubernetes.io.tls) \n" +
		"kubectl view-cert mysecret \n" +
		"\n" +
		"# View certificate from a specific key in a specific secret (secret type could be anything as long as secret key contains base64 pem encoded data) \n" +
		"kubectl view-cert mysecret mykey \n",

	RunE:    run,
	Version: versionString(),
}

// versionString returns the version prefixed by 'v'
// or an empty string if no version has been populated by goreleaser.
// In this case, the --version flag will not be added by cobra.
func versionString() string {
	if version == "" {
		return ""
	}
	return "v" + version
}

func init() {
	klog.InitFlags(nil)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	// hide all glog flags except for -v
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name != "v" {
			pflag.Lookup(f.Name).Hidden = true
		}
	})

	cf = genericclioptions.NewConfigFlags(true)

	rootCmd.Flags().BoolP(allNamespacesFlag, "A", false, "Query all objects in all API groups, both namespaced and non-namespaced")
	rootCmd.Flags().BoolP(expiredFlag, "E", false, "Show only expired certificates")
	rootCmd.Flags().BoolP(showCaCertFlag, "S", false, "Show CA certificates")
	rootCmd.Flags().IntP(expiredDaysFromNowFlag, "D", 0, "Show expired certificates at date in future (now plus number of days)")

	cf.AddFlags(rootCmd.Flags())
	if err := flag.Set("logtostderr", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set logtostderr flag: %v\n", err)
		os.Exit(1)
	}
}

func getNamespace() string {
	if v := *cf.Namespace; v != "" {
		return v
	}
	clientConfig := cf.ToRawKubeConfigLoader()
	defaultNamespace, _, err := clientConfig.Namespace()
	if err != nil {
		defaultNamespace = "default"
	}
	return defaultNamespace
}

func main() {
	defer klog.Flush()
	if err := rootCmd.Execute(); err != nil {
		return
	}
}

func parseFlagsAndArguments(command *cobra.Command, args []string) (allNs, expired, showCaCert bool, expiredInDays int, secretName, secretKey string) {
	allNs, err := command.Flags().GetBool(allNamespacesFlag)
	if err != nil {
		allNs = false
	}

	expired, err = command.Flags().GetBool(expiredFlag)
	if err != nil {
		expired = false
	}

	showCaCert, err = command.Flags().GetBool(showCaCertFlag)
	if err != nil {
		showCaCert = false
	}

	expiredInDays, err = command.Flags().GetInt(expiredDaysFromNowFlag)
	if err != nil {
		expiredInDays = 0
	}

	if len(args) > 0 {
		secretName = args[0]
	}

	if len(args) > 1 {
		secretKey = args[1]
	}

	return
}

func run(command *cobra.Command, args []string) error {
	klog.V(1).Info("Run kubectl view-cert")

	ctx := context.Background()

	// Parse flags and arguments
	allNs, expired, showCaCert, expiredInDays, secretName, secretKey := parseFlagsAndArguments(command, args)

	// Validate inputs
	if allNs && secretName != "" {
		return errors.New("a resource cannot be retrieved by name across all namespaces")
	}

	if secretName != "" && (expired || expiredInDays != 0 || showCaCert) {
		return errors.New("when specifying secret name, no flags are allowed, only a second argument with secret key is allowed")
	}

	// Prepare clients to interact with kubernetes api
	ns, ri, err := getResourceInterface(allNs, secretName)
	if err != nil {
		return err
	}

	if secretName != "" {
		datas, err := getData(ctx, secretName, ns, secretKey, ri)
		if err != nil {
			return err
		}

		// Display
		err = displayDatas(datas)
		if err != nil {
			return err
		}
	} else {
		datas, err := getDatas(ctx, ri)
		if err != nil {
			return err
		}

		// Filter Datas
		filteredDatas := datas
		klog.V(1).Infof("Number of certificates found %d", len(datas))

		klog.V(1).Infof("expired %t expiredInDays %d", expired, expiredInDays)
		if expired && expiredInDays == 0 {
			filteredDatas = filterWithDate(datas, time.Now().UTC(), dateAfterFilter)
		} else if expiredInDays > 0 {
			filteredDatas = filterWithDate(datas, time.Now().AddDate(0, 0, expiredInDays).UTC(), dateAfterFilter)
		}

		if !showCaCert {
			filteredDatas = filter(filteredDatas, noCaCertFilter)
		}

		// Display
		err = displayDatas(filteredDatas)
		if err != nil {
			return err
		}
	}

	return nil
}

func getDatas(ctx context.Context, ri dynamic.ResourceInterface) ([]*Certificate, error) {
	klog.V(1).Info("Scanning secrets")
	datas := make([]*Certificate, 0)

	tlsSecrets, err := ri.List(ctx, v1.ListOptions{FieldSelector: "type=kubernetes.io/tls"})
	if err != nil {
		return datas, fmt.Errorf("failed to get secrets: %w", err)
	}

	for _, tlsSecret := range tlsSecrets.Items {
		certData, caCertData, err := parseData(tlsSecret.GetNamespace(), tlsSecret.GetName(), tlsSecret.Object, "")
		if err != nil {
			return datas, err
		}

		if certData != nil {
			datas = append(datas, certData)
		}

		if caCertData != nil {
			datas = append(datas, caCertData)
		}
	}

	return datas, nil
}

func getData(ctx context.Context, secretName, ns, secretKey string, ri dynamic.ResourceInterface) ([]*Certificate, error) {
	klog.V(1).Infof("Get secret name %s in namespace %s", secretName, ns)

	datas := make([]*Certificate, 0)

	secret, err := ri.Get(ctx, secretName, v1.GetOptions{})
	if err != nil {
		return datas, fmt.Errorf("failed to get secret with name %s: %w", secretName, err)
	}

	certData, caCertData, err := parseData(ns, secretName, secret.Object, secretKey)
	if err != nil {
		return datas, err
	}

	if certData != nil {
		datas = append(datas, certData)
	}

	if caCertData != nil {
		datas = append(datas, caCertData)
	}

	return datas, nil
}

func displayDatas(datas []*Certificate) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "    ")
	return encoder.Encode(&datas)
}

func getResourceInterface(allNs bool, secretName string) (string, dynamic.ResourceInterface, error) {
	restConfig, err := cf.ToRESTConfig()
	if err != nil {
		return "", nil, err
	}
	restConfig.QPS = 1000
	restConfig.Burst = 1000
	dyn, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to construct dynamic client: %w", err)
	}

	ns := getNamespace()
	klog.V(1).Infof("namespace=%s allNamespaces=%v", ns, allNs)

	// Check arguments
	if secretName != "" && ns == "" {
		err = errors.New("secretName passed as argument but blank namespace")
		return "", nil, err
	}

	secretGroupVersionResource := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	var ri dynamic.ResourceInterface
	if allNs && secretName == "" {
		ri = dyn.Resource(secretGroupVersionResource)
	} else {
		ri = dyn.Resource(secretGroupVersionResource).Namespace(ns)
	}

	return ns, ri, nil
}

func parseData(ns, secretName string, data map[string]interface{}, secretKey string) (certData, caCertData *Certificate, err error) {
	secretType := fmt.Sprintf("%v", data["type"])
	klog.V(1).Infof("secret type %s", secretType)

	klog.V(1).Infof("%s/%s", ns, secretName)

	secretCertData, err := parse.NewCertificateData(ns, secretName, data, secretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse secret with name %s in namespace %s %v", secretName, ns, err)
	}

	parsedCerts, err := secretCertData.ParseCertificates()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse certificates for secret %s in namespace %s %v", secretName, ns, err)
	}

	if parsedCerts.Certificate != nil {
		certData = &Certificate{
			SecretName:   parsedCerts.SecretName,
			Namespace:    parsedCerts.Namespace,
			IsCA:         parsedCerts.Certificate.IsCA,
			Issuer:       parsedCerts.Certificate.Issuer.String(),
			SerialNumber: fmt.Sprintf("%x", parsedCerts.Certificate.SerialNumber),
			Subject:      parsedCerts.Certificate.Subject.String(),
			Validity: CertificateValidity{
				NotBefore: parsedCerts.Certificate.NotBefore,
				NotAfter:  parsedCerts.Certificate.NotAfter,
			},
			Version: parsedCerts.Certificate.Version,
		}
	}

	if parsedCerts.CaCertificate != nil {
		caCertData = &Certificate{
			SecretName:   parsedCerts.SecretName,
			Namespace:    parsedCerts.Namespace,
			IsCA:         parsedCerts.CaCertificate.IsCA,
			Issuer:       parsedCerts.CaCertificate.Issuer.String(),
			SerialNumber: fmt.Sprintf("%x", parsedCerts.CaCertificate.SerialNumber),
			Subject:      parsedCerts.CaCertificate.Subject.String(),
			Validity: CertificateValidity{
				NotBefore: parsedCerts.CaCertificate.NotBefore,
				NotAfter:  parsedCerts.CaCertificate.NotAfter,
			},
			Version: parsedCerts.CaCertificate.Version,
		}
	}

	return certData, caCertData, err
}
