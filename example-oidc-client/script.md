 Mycelium is a Kubernetes-centric identity federation framework.
 Before we dive deep into the capabilities of Mycelium, let's try to understand what problem it is trying to solve and where it fits in the Kubernetes infrastructure
 In today's modern-day landscape, it is very common for a Kubernetes workload to access one or more cloud providers to consume their cloud resources.
 So managing credentials and securing the communication channel becomes very critical.
 We, of course, do not want to use any static credentials; that would be dangerous.
 So workload identity federation is the way to go.
 We will talk about this at a very high level at the beginning of the video, and as we progress into the video, we will get into the nitty gritties
 Workload identity federation implements client credentials workflow for machine-to-machine communication, which is part of OAuth 2.0. At a high level, two things must happen: one, the calling entity, which is the pod in our case, needs to obtain a jwt.
 And the workload sends this jwt to the workload identity provider that has been configured in the cloud. The workload identity provider must be configured to trust the issuer of the jwt so that the workload can get short-term credentials back in an exchange for the jwt to consume cloud resources.
 So what are the ways in which a pod can obtain a jwt?
 First, and the most easiest and obvious approach is to use the cluster's kube-api server to issue jwts. So the kube-api server issues the jwt; the kubelet makes this available in the pod.
 In the cloud the OIDC server corresponding to this Kubernetes cluster must be added as a trusted issuer in the workload identity provider.
 So the URL of the OIDC server for the Kubernetes cluster is added so that the cloud can use that URL to fetch the public keys of the corresponding private keys, which were used to sign the jwts. The next option is to use spiffe.
 spiffe is a workload attestation framework. So the pod leverages the spire agent, which is running on the node, to connect with the spire server and mint a svid jwt.
 svid can be of type certificate or jwt; we are mainly concerned with jwt in this case.
 Assuming that the node attestation and workload attestation have been cleared, the spire server will issue a jwt back to the agent, and that is made available to the pod. This way, the pod can get a jwt.
 One interesting thing to note here is that the issuer of the jwt is not the Kubernetes controller; it is coming from an external entity. In the cloud the spire server's OIDC discovery endpoint must be added to the workload identity provider so that the cloud can access the corresponding signing public keys.
 Third option is to use an external identity provider like Okta, Auth0, Keycloak, DEX, so many others.
 In order for the pod to fetch a jwt from an external IdP, the pod will first have to connect to it.
 So in order for it to connect to the external IdP, the workload must be registered with the external identity provider. So how does this happen?
 How can a workload that is a pod, how can it be registered in the identity provider? Because we deploy a lot of applications very quickly, and especially in the age of AI, the rate of development is extremely high.
 So how can a pod get registered in external IdPs and also be made aware the and also be made aware of the credentials it must use to connect to the said IdP to fetch the jwt? We will park this question for now and revisit this in a few slides.
 In the cloud the OIDC discovery URL of the IDP is made available to the workload identity provider.

 Let's now go through some workflows and compare these three approaches.
 signing keys:
 When it comes to signing keys, Kubernetes API server has one set of keys, and irrespective of the namespace in which the workload exists, all jwts are signed by the same set of keys. In case of spiffe, all the clusters that are part of the same trust domain are signed using the same set of keys.
 In case of external IdPs, it may vary. If we choose to use solutions like Okta or Keycloak, then they present unique keys per organization or realm, respectively.
 If we choose a solution like Auth0, then it is a common signing key for the tenant, and all the jwts that are issued under the tenant will have the same signing key.
 Now, as we established earlier, workloads typically access cloud resources or consume cloud resources from one or more clouds.
 establish trust:
 So how do we establish trust in each of these scenarios? When it comes to Kubernetes, because the Kubernetes controller is issuing the jwt, each Kubernetes has its own OIDC server.
 Either the cluster itself can be turned into an OIDC server, or if we are using a managed Kubernetes cluster, the cloud will create an OIDC server and attach it to the Kubernetes cluster. One way or the other, the Kubernetes OIDC server must be added to all the target clouds.
 In case of spiffe, because multiple Kubernetes clusters can be part of the same trusted domain, a single trusted domain will have to be added to all the target cloud accounts or cloud projects.
 Same is true for an external IdP. 
 Generally, a given organization or an environment or a combination of both will have trust domain and an IDP, let's take an example.
 adding k8s cluster's OIDC endpoint to every target cloud creates a mesh 
 like design. Using common trust domain or an external IDP for an org/ environment or a combination of both will create a hub-spoke design.

 adding new clusters:
 for kube-api, the new cluster must be confifured for workload identity federation in all target clouds 
 for spiffe the new cluster is added to the same trust doamin, since the target clouds trust it already there is nothing to do.
 for external IDP the new cluster is added to the same IDP, since the target clouds trust it already there is nothing to do.

 adding a new target cloud:
 for kube-api, every source cluster must be confifured for workload identity federation in the new target cloud
 for spiffe the new cloud is configured to trust the spire issuer, since the source clusters are part of the trusted domain they can immediently aceess the new cloud.
 for external IDP the new cloud is configured to trust the IDP, since the source clusters are registered with the IDP they can immediently aceess the new cloud.
 
 So if we put all those together and condense it, we arrive at some objectives, these are actions that must be perfomed in a given scenario:
 1) When we use kube-api-server to issue the jwts, each of those cluster OIDC servers must be configured in every target cloud.
 2) And in case of spiffe, the trust domain that points to the OIDC discovery endpoint must be added to all the target clouds. 
 3) In case of an external IdP, it is not enough to add the external IdP to the cloud that is the target cloud, but we must also register the workload, the Kubernetes workload, with the external IdP.
 And this is the question that we had parked earlier. So we need something that can register a workload in the external identity provider and make those credentials available to the workload so that the workload can use those credentials to mint a jwt and then connect with the workload identity provider to fetch short-term credentials.
 4) For additional security, if we require every namespace to be signed with unique signing keys, then using an external identity provider like Okta or Keycloak will help us in that scenario.
 5) And if we want fewer connections from our clusters to target clouds, then using spiffe or an external IdP becomes essential, because they are central identity providers, unlike the Kubernetes API, which is, of course, pertains to a single cluster.
 So these objectives reveal something very interesting, which is that there is a way there is a clear correlation between Kubernetes identity constructs and identity provider constructs and cloud provider constructs.
 That is, from an identity IAM perspective, Kubernetes native constructs map to identity provider constructs and also to workload identity federation constructs in the cloud.
 We'll see how that looks like.
 In case of Keycloak, a Kubernetes namespace would be mapped to a realm, and a service account will be a client ID within the said realm. In case of Auth0, a namespace will be a resource server or an API, and the service account will be an application.
 In case of spiffe, because there is no registration per se, the spire agent will take care of that as part of workload attestation. The only thing that needs to be done is to add the spiffe issuer to the cloud as a trusted issuer.
 So the trust domain becomes an identity provider or a workload identity provider in the cloud.
 In case of AWS and GCP, the cloud providers, in AWS, Kubernetes namespace is mapped to an identity provider within IAM.
 The service account is then used in the in establishing the trust policy to decide if the service account is allowed to assume a given role or not. The service account, which is also the client ID, is added to the audience list in the identity provider as well.
 In case of GCP, the Kubernetes namespace is turned into is mapped to a workload identity provider, and the service account name or the client ID that is that corresponds to the service account name, if it is registered with an external IdP, is used to grant access to the workload to impersonate any service account of choice.
 And this is where Mycelium comes in. So Mycelium does all the heavy lifting.
 So the philosophy of Mycelium is that if the if Kubernetes is where the workload lives, its identity should be declaratively defined and governed from Kubernetes as well. Kubernetes namespaces and service accounts define the identity of the workload, and that becomes the source of truth.
 Mycelium takes that and then projects it onto the configured identity providers and configured target clouds. And because Mycelium is a Kubernetes operator, it continuously reconciles Kubernetes native identity constructs like namespace and service account with their corresponding representations in identity providers and cloud providers.
 This way, any changes in the Kubernetes identity constructs will be automatically reflected in identity providers and cloud providers, thereby keeping the identity federation model aligned from Kubernetes to IdP to cloud provider automatically.