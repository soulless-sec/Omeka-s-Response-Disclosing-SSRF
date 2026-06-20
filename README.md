## Potential Response-Disclosing SSRF in Omeka S URL Media Ingester

## Summary:

I identified a Server-Side Request Forgery (SSRF) issue in the URL Media Ingester functionality of Omeka S 4.2.1.

The application allows authenticated users with media creation privileges to supply arbitrary URLs for media ingestion. During testing, I confirmed that Omeka S performs server-side requests to loopback addresses and stores the retrieved response as media content.

Because the retrieved response is subsequently accessible through the application interface, this is a response-disclosing SSRF primitive.

**Affected Version**:
- Omeka S 4.2.1

**Vulnerability Type**:
- CWE-918: Server-Side Request Forgery (SSRF)

---

## Technical Details & Vulnerable Code:

The vulnerability exists because the application accepts a user-supplied URL and fetches it without implementing network-layer access controls (such as blocking local, private, or link-local IP addresses).

Here is the exact step-by-step code trace where the vulnerability occurs:

  **1. Incomplete URL Validation ( Url.php )**

In  application/src/Media/Ingester/Url.php , the application accepts the  ingest_url  parameter. It only checks if the URL is syntactically valid and absolute. It explicitly fails to check the hostname or IP address.

```
 // Location: application/src/Media/Ingester/Url.php (Lines 57-61)
   
    uri = newHttpUri()data['ingest_url']);
   
    // VULNERABILITY: Only checks syntax. 127.0.0.1 and 169.254.169.254 pass this check.
    if (!($uri->isValid() && $uri->isAbsolute())) {
        $errorStore->addError('ingest_url', 'Invalid ingest URL');
        return;
    }
   
    // Passes the unfiltered URL to the downloader
    tempFile = this - >downloader - >download()uri, $errorStore);
```
  **2. Unrestricted HTTP Request ( Downloader.php )**

The URI is passed to  application/src/File/Downloader.php . The application uses the  Laminas\Http\Client  to dispatch the request. Because no proxy or IP restriction is configured, the server faithfully connects to whatever internal or external IP is supplied, and writes the response stream directly to a temporary file.

```
// Location: application/src/File/Downloader.php (Lines 57-64)
   
    $client = $this->services->get('Omeka\HttpClient');
    $tempFile = $this->tempFileFactory->build();
   
    // VULNERABILITY: Executes the request to the unfiltered destination
    client - >setUri()uri)->setStream($tempFile->getTempPath());
   
    while (true) {
        try {
            $response = $client->send(); // The SSRF triggers here
            break;
    // ...
```
  **3. Dangerous Default Whitelists ( SettingForm.php )**

Once downloaded, the file goes through  Validator::validate() . The validator checks the file's MIME type and extension. However, Omeka S's default configuration explicitly permits  text/plain  and  .txt.

Since internal HTTP APIs and cloud metadata endpoints (like AWS IMDS) typically return plain text, they easily bypass this validation layer.

```
// Location: application/src/Form/SettingForm.php
   
    // Default allowed media types (Line 72)
    const MEDIA_TYPE_WHITELIST = [
        // ...
        'text/css',
        'text/plain',      // Allows internal text/JSON/metadata responses
        'text/richtext',
        // ...
    ];
   
    // Default allowed extensions (Line 96)
    const EXTENSION_WHITELIST = [
        // ...
        'tiff', 'txt', 'wav', 'wax', 'webm', 'webp', // Allows .txt mapping
    ];
```
As a result, an authenticated user can cause the server to issue HTTP requests to internal destinations, successfully pass file validation, and retrieve the stored response.

---

## Impact:

An authenticated user capable of creating media can cause the server to send HTTP requests to destinations that may not otherwise be reachable from the attacker.

Because the response is returned to the user, the impacts include:

- Accessing and reading localhost services.
- Reading data from internal corporate network resources and unauthenticated REST APIs.
- Critical Risk: Extracting highly sensitive secrets from Cloud Metadata services (e.g., AWS IMDSv1  http://169.254.169.254/latest/meta-data/ ) if the Omeka S instance is hosted in the cloud.
- Internal service discovery and network mapping (via verbose validation error messages when files are rejected).

---

## Attack Requirements:

- Valid authenticated account.
- Permission to create media using the URL Ingester (e.g., Researcher, Author, or Admin).

---

**CVSS v3.1 (Estimated)**:
  
  - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N

**Estimated Score**: 7.7 (High)

---

## Suggested Remediation:

Before executing outbound requests in  application/src/File/Downloader.php :

  1. Resolve destination hostnames to their underlying IP address.
  2. Block requests if the resolved IP matches internal or private ranges:
    - 127.0.0.0/8  (Loopback)
    - 10.0.0.0/8 ,  172.16.0.0/12 ,  192.168.0.0/16  (RFC1918 Private Networks)
    - 169.254.0.0/16  (Cloud Metadata/Link-Local)
    - ::1  (IPv6 Loopback)
  3. Prevent DNS Rebinding (TOCTOU): Ensure the  Laminas\Http\Client  connects explicitly to the validated IP address rather than the original hostname. Pass the original hostname via the HTTP  Host  header to maintain support for virtual hosting.
  4. Validate Redirects: Ensure the HTTP client validates the destination IP of any HTTP redirects before following them.

---

## Final Assessment:

During testing, I confirmed that:

  - User-controlled URLs are fetched server-side without network isolation checks.
  - Requests to localhost and private IPs are natively permitted.
  - Retrieved responses are stored on the server.
  - Retrieved responses are disclosed through the application interface because default file validation rules authorize plain text storage.

Based on this code and runtime behavior, I believe this constitutes a response-disclosing SSRF affecting the URL Media Ingester functionality.

---

## Researcher Information:

  - **Name**: soulless
  - **Date**: June 19, 2026
