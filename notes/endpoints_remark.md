# Remarks

## /v2/keys?identity={identity}

- This endpoint has the usage of uploading OTKs (EC and PQ) during registration and SPKs when expired (re-uploading). SPKs are firstly uploaded with **/v1/registration**.

- Open question: 
    - what happens if it is injected **/v1/registration** twice?\
    - Can you use **/v2/keys** to upload SPKs for the first time? 