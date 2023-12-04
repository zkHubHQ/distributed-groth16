# Azure Commands

### Connecting to Azure box

Make sure you download the private key for the SSH while Azure VM creation.
Grant only the permission for the user to access the .pem file using `chmod 600 [path-to-pem-file]`.

```bash
ssh -i ~/Downloads/azure/ssh-keys/zk-saas-test-runner_key.pem azureuser@4.240.85.25
```
