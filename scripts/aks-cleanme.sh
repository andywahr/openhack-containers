kubectl delete deployments --cascade=true --all --namesapce web
kubectl delete deployments --cascade=true --all --namesapce api
kubectl delete services --cascade=true --all --namesapce web
kubectl delete services --cascade=true --all --namesapce api
