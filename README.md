# Function which demonstrates the "secrects" utilisation

This function is used to validate IDCS tokens to a IDCS application
REF https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-oauth2-v1-introspect-post.html


** Follow the content of the debug_bucket **

 


## Pre-requisites

### Configure OCI Settings

Configure Dynamic Groups, Dynamic Group Policues,  Instant Principal 

## Create secrets to  protect sensitive information

Follow the steps describe in the blog 

### Create an app to host this function

`fn create app --annotation oracle.com/oci/subnetIds=<SUBNETS>  fn-test-faas-application`




**Check**

`fn inspect app fn-secrects-app`

## Deploy the app

`fn -v deploy --app fn-test-faas-application`

`fn ls funcs fn-test-faas-application`

## Test

### Standalone

Generate an IDCS valid token. This could be done by logging to the IDCS console, and click on the link generate TOKEN

echo -n '{"token":"YOURVALIDIDCS_TOKEN","type":"TOKEN","expires_in":3600}' | DEBUG=1 fn invoke fncomputeapp auth2-blog

{"active":true,"scope":"urn:opc:idm:g.identitysourcetemplate_r urn:opc:idm:t.groups.members_r urn:opc:idm:t.groups.members urn:opc:idm:t.app urn:opc:idm:t.user.lockedstatechanger urn:opc:idm:g.cert urn:opc:idm:t.idbridge.admin urn:opc:idm:t.termsofuse urn:opc:idm:t.idcsrpts urn:opc:idm:t.requests urn:opc:idm:t.user.manager urn:opc:idm:t.helpdesk.security urn:opc:idm:t.security.client urn:opc:idm:t.settings_r urn:opc:idm:g.apptemplate_r urn:opc:idm:t.bulk.user urn:opc:idm:t.diagnostics_r urn:opc:idm:t.idb_containers urn:opc:idm:t.idbridge.user urn:opc:idm:t.user.me urn:opc:idm:g.all_r urn:opc:idm:t.idbridge_r urn:opc:idm:t.mfa_r urn:opc:idm:t.user.security urn:opc:idm:t.user.resetpassword urn:opc:idm:t.groups_r urn:opc:idm:t.diagnostics urn:opc:idm:t.audit_r urn:opc:idm:t.job.app urn:opc:idm:t.user.signin urn:opc:idm:t.oauthconsents urn:opc:idm:t.users_r urn:opc:idm:t.somi urn:opc:idm:t.mfa.enroll urn:opc:idm:g.sharedfiles urn:opc:idm:t.helpdesk.user urn:opc:idm:t.res.importexport urn:opc:idm:t.job.identity urn:opc:idm:t.customclaims urn:opc:idm:t.db.admin urn:opc:idm:t.saml urn:opc:idm:t.mfa urn:opc:idm:t.posixviewer urn:opc:idm:t.apponly_r urn:opc:idm:t.schemas urn:opc:idm:t.mfa.useradmin urn:opc:idm:t.user.manager.job urn:opc:idm:t.cloudgate_r urn:opc:idm:t.oauth urn:opc:idm:t.groups urn:opc:idm:t.job.importexport urn:opc:idm:t.idbridge.unmapped.idcsattributes urn:opc:idm:t.krb.admin urn:opc:idm:t.namedappadmin urn:opc:idm:t.blkrpts urn:opc:idm:t.selfregistrationprofile urn:opc:idm:t.grants urn:opc:idm:t.user.authenticate urn:opc:idm:t.authentication urn:opc:idm:t.container urn:opc:idm:t.images urn:opc:idm:t.bulk urn:opc:idm:t.delegated.group.members urn:opc:idm:t.job.search urn:opc:idm:t.idbridge urn:opc:idm:t.appservices urn:opc:idm:t.settings urn:opc:idm:t.user.manager.security urn:opc:idm:t.user.verifyemail urn:opc:idm:t.cloudgate urn:opc:idm:t.idbridge.sourceevent urn:opc:idm:t.user.changepassword urn:opc:idm:t.idb_containers_r urn:opc:idm:t.policy urn:opc:idm:t.users urn:opc:idm:t.reports urn:opc:idm:t.encryptionkey urn:opc:idm:t.user.mecreate urn:opc:idm:t.krb.update urn:opc:idm:g.idcsrptsmeta_r urn:opc:idm:t.adaptive_r urn:opc:idm:t.user.forgotpassword","client_id":"XXXXXXXXXX","prn":"","expiresAt":"2020-04-06T05:41:06Z","context":null,"wwwAuthenticate":"","token_type":"JWT"}
