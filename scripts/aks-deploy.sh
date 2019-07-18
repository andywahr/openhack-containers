#!/bin/bash

# The MIT License (MIT)
#
# Copyright (c) 2019 Microsoft Azure
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Define a variable for the AKS cluster name, resource group, and location
# Provide your own unique aksname within the Azure AD tenant
suffix="table4-part6"
aksname="aksTrips-$suffix"
resourcegroup="teamResources"
location="southcentralus"
adgroupname="Cluster-Admin-aksTrips-table4-part4"

# Create the Azure AD application
serverApplicationId=$(az ad app create \
    --display-name "${aksname}Server" \
    --identifier-uris "https://${aksname}Server" \
    --query appId -o tsv)

# Update the application group memebership claims
az ad app update --id $serverApplicationId --set groupMembershipClaims=All

# Create a service principal for the Azure AD application
az ad sp create --id $serverApplicationId

# Get the service principal secret
serverApplicationSecret=$(az ad sp credential reset \
    --name $serverApplicationId \
    --credential-description "AKSPassword" \
    --query password -o tsv)

# Add permissions for the Azure AD app to read directory data, sign in and read
# user profile, and read directory data
az ad app permission add \
    --id $serverApplicationId \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope 06da0dbc-49e2-44d2-8312-53f166ab848a=Scope 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

# Grant permissions for the permissions assigned in the previous step
# You must be the Azure AD tenant admin for these steps to successfully complete
az ad app permission grant --id $serverApplicationId --api 00000003-0000-0000-c000-000000000000
az ad app permission admin-consent --id  $serverApplicationId

# Create the Azure AD client application
clientApplicationId=$(az ad app create --display-name "${aksname}Client" --native-app --reply-urls "https://${aksname}Client" --query appId -o tsv)

# Create a service principal for the client application
az ad sp create --id $clientApplicationId

# Get the oAuth2 ID for the server app to allow authentication flow
oAuthPermissionId=$(az ad app show --id $serverApplicationId --query "oauth2Permissions[0].id" -o tsv)

# Assign permissions for the client and server applications to communicate with each other
az ad app permission add --id $clientApplicationId --api $serverApplicationId --api-permissions $oAuthPermissionId=Scope
az ad app permission grant --id $clientApplicationId --api $serverApplicationId

# Create a resource group the AKS cluster
az group create --name $resourcegroup --location $location

# Get the Azure AD tenant ID to integrate with the AKS cluster
tenantId=$(az account show --query tenantId -o tsv)
subscriptionId=$(az account show --query id -o tsv)

# Create subnet for AKS and get subnetId
az network vnet subnet create --name kubnet --address-prefixes 10.0.1.0/24 --vnet-name vnet --resource-group teamResources
subnetId=$(az network vnet subnet show -g teamResources --vnet-name vnet -n kubnet --query "id" -o tsv)

# Create the AKS cluster and provide all the Azure AD integration parameters
az aks create \
  --resource-group $resourcegroup \
  --name $aksname \
  --node-count 3 \
  --generate-ssh-keys \
  --aad-server-app-id $serverApplicationId \
  --aad-server-app-secret $serverApplicationSecret \
  --aad-client-app-id $clientApplicationId \
  --aad-tenant-id $tenantId \
  --dns-service-ip 10.0.2.10 \
  --service-cidr 10.0.2.0/24 \
  --network-plugin azure \
  --vnet-subnet-id $subnetId

# Get the admin credentials for the kubeconfig context
az aks get-credentials --resource-group $resourcegroup --name $aksname --admin

ACR_NAME="registry3M84331"

# Get the id of the service principal configured for AKS
CLIENT_ID=$(az aks show --resource-group $resourcegroup --name $aksname --query "servicePrincipalProfile.clientId" --output tsv)

# Get the ACR registry resource id
ACR_ID=$(az acr show --name $ACR_NAME --resource-group $resourcegroup --query "id" --output tsv)

# Create role assignment
az role assignment create --assignee $CLIENT_ID --role acrpull --scope $ACR_ID

#Get AKS Cluster ID
AKS_ID=$(az aks show \
    --resource-group $resourcegroup --name $aksname \
    --query id -o tsv)

# Create Cluster Admin AD Group
CLUSTERADMIN_ID=$(az ad group create --display-name $adgroupname --mail-nickname $adgroupname --query objectId -o tsv)

# Add all hack accounts to group
HACKER1=$(az ad user show --upn-or-object-id hacker1y01@OTAPRD320ops.onmicrosoft.com  --query objectId -o tsv)
az ad group member add --group $adgroupname --member-id $HACKER1
HACKER2=$(az ad user show --upn-or-object-id hacker2eyv@OTAPRD320ops.onmicrosoft.com  --query objectId -o tsv)
az ad group member add --group $adgroupname --member-id $HACKER2
HACKER3=$(az ad user show --upn-or-object-id hacker35o7@OTAPRD320ops.onmicrosoft.com  --query objectId -o tsv)
az ad group member add --group $adgroupname --member-id $HACKER3
HACKER4=$(az ad user show --upn-or-object-id hacker4awb@OTAPRD320ops.onmicrosoft.com  --query objectId -o tsv)
az ad group member add --group $adgroupname --member-id $HACKER4

# Assign AD Group to Admin Role
az role assignment create \
  --assignee $CLUSTERADMIN_ID \
  --role "Azure Kubernetes Service Cluster Admin Role" \
  --scope $AKS_ID

#Create Managed Identity for Pods to Auth against Key Vault
keyVaultIdentityName="KeyVaultIdentity-$aksname"
az identity create -g $resourcegroup --name $keyVaultIdentityName
#Get Info From Resource Group - identity
keyVaultIdentityId=$(az identity show -g $resourcegroup --name $keyVaultIdentityName -o tsv --query "id")
#Get Info From Resource Group - clientId
keyVaultClientId=$(az identity show -g $resourcegroup --name $keyVaultIdentityName -o tsv --query "clientId")

az role assignment create --role "Managed Identity Operator" --assignee $CLIENT_ID --scope $keyVaultIdentityId

#Create Azure Key Vault
keyVaultName="kv$suffix"
az keyvault create -g $resourcegroup --name $keyVaultName
# set policy to access keys in your Key Vault
az keyvault set-policy -g $resourcegroup -n $keyVaultName --secret-permissions get --spn $keyVaultClientId

# Create SQL Secrets
az keyvault secret  set --name "SQL-USER" --value "sqladmin3M84331" --vault-name $keyVaultName 
az keyvault secret  set --name "SQL-PASSWORD" --value "sO7z53Sy8" --vault-name $keyVaultName 
az keyvault secret  set --name "SQL-SERVER" --value "sqlserver3m84331.database.windows.net" --vault-name $keyVaultName  

# Install the KeyVault FlexVol and the Azure AD Identitiy (Managed Identities) for Pods
kubectl create -f https://raw.githubusercontent.com/Azure/kubernetes-keyvault-flexvol/master/deployment/kv-flexvol-installer.yaml
kubectl apply -f https://raw.githubusercontent.com/Azure/aad-pod-identity/master/deploy/infra/deployment-rbac.yaml

#Clean temp dir
rm ../runMe/*
mkdir ../runMe
yes | cp -f ../yaml/* ../runMe

#evil Text replacement fun for Identity
escapedKeyVaultIdentityId=$(sed "s.\/.\\\/.g" <<< $keyVaultIdentityId)
escapedKeyVaultClientId=$(sed "s.\/.\\\/.g" <<< $keyVaultClientId)

clientIdReplaceRegex="s/\\\$CLIENTID\\\$/$escapedKeyVaultClientId/g"
sed -i -e $clientIdReplaceRegex ../runMe/001-adIdentity.yaml

idReplaceRegex="s/\\\$ID\\\$/$escapedKeyVaultIdentityId/g"
sed -i -e $idReplaceRegex ../runMe/001-adIdentity.yaml

#Install HELM
#curl -LO https://git.io/get_helm.sh
#chmod 700 get_helm.sh
#./get_helm.sh
helm repo update
helm init --service-account tiller 
helm install stable/nginx-ingress --namespace web --set controller.replicaCount=2 --set controller.nodeSelector."beta\.kubernetes\.io/os"=linux --set defaultBackend.nodeSelector."beta\.kubernetes\.io/os"=linux
helm install stable/prometheus-operator --name prometheus-operator --namespace monitoring

#Add Azure Container Insights (Monitor)
az aks enable-addons -a monitoring -n $aksname -g $resourcegroup

#Add Istio
ISTIO_VERSION=1.1.3
curl -sL "https://github.com/istio/istio/releases/download/$ISTIO_VERSION/istio-$ISTIO_VERSION-linux.tar.gz" | tar xz

cd istio-$ISTIO_VERSION
sudo cp ./bin/istioctl /usr/local/bin/istioctl
sudo chmod +x /usr/local/bin/istioctl

# Generate the bash completion file and source it in your current shell
mkdir -p ~/completions && istioctl collateral --bash -o ~/completions
source ~/completions/istioctl.bash

# Source the bash completion file in your .bashrc so that the command-line completions
# are permanently available in your shell
echo "source ~/completions/istioctl.bash" >> ~/.bashrc

helm install install/kubernetes/helm/istio-init --name istio-init --namespace istio-system

GRAFANA_USERNAME=$(echo -n "grafana" | base64)
GRAFANA_PASSPHRASE=$(echo -n "REPLACE_WITH_YOUR_SECURE_PASSWORD" | base64)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: grafana
  namespace: istio-system
  labels:
    app: grafana
type: Opaque
data:
  username: $GRAFANA_USERNAME
  passphrase: $GRAFANA_PASSPHRASE
EOF

KIALI_USERNAME=$(echo -n "kiali" | base64)
KIALI_PASSPHRASE=$(echo -n "REPLACE_WITH_YOUR_SECURE_PASSWORD" | base64)

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: kiali
  namespace: istio-system
  labels:
    app: kiali
type: Opaque
data:
  username: $KIALI_USERNAME
  passphrase: $KIALI_PASSPHRASE
EOF

helm install install/kubernetes/helm/istio --name istio --namespace istio-system \
  --set global.controlPlaneSecurityEnabled=true \
  --set mixer.adapters.useAdapterCRDs=false \
  --set grafana.enabled=true --set grafana.security.enabled=true \
  --set tracing.enabled=true \
  --set kiali.enabled=true

#Add Istio to Web and App
kubectl label namespace web istio-injection=enabled
kubectl label namespace api istio-injection=enabled


#evil Text replacement fun for all 100 yamls
for file in ../runMe/100*
do
  keyVaultNameChange="s.\\\$KEYVAULTNAME\\\$.$keyVaultName.g"
  resourceGroupChange="s.\\\$RESOURCEGROUP\\\$.$resourcegroup.g"
  subscriptionChange="s.\\\$SUBSCRIPTION\\\$.$subscriptionId.g"
  tenantChange="s.\\\$TENANT\\\$.$tenantId.g"

  sed -i -e $keyVaultNameChange $file
  sed -i -e $resourceGroupChange $file
  sed -i -e $subscriptionChange $file
  sed -i -e $tenantChange $file
done       

# Run deployments
for file in ../runMe/*
do
  kubectl apply -f "$file"
done

rm ../runMe/*

