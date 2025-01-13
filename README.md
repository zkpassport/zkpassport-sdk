# zkpassport-sdk

## Installation

```
npm install @zkpassport/sdk
```

## How to use

```ts
import { ZKPassport, EU_COUNTRIES } from '@zkpassport/sdk'

// Replace with your domain
const zkPassport = new ZKPassport('demo.zkpassport.id')

// Specify your app name, logo and the purpose of the request
// you'll send to your visitors or users
const queryBuilder = await zkPassport.request({
  name: 'ZKPassport',
  logo: 'https://zkpassport.id/logo.png',
  purpose: 'Prove you are an adult from the EU but not from Scandinavia',
  // The scope is optional and can be used to scope the nullifier
  // of the proof to a specific use case
  // By default, the nullifier is scoped to your domain name only
  scope: 'eu-adult-not-scandinavia',
})

// Specify the data you want to disclose
// Then you can call the `done` method to get the url and the callbacks to follow the progress
// and get back the result along with the proof
// The example below requests to disclose the firstname, prove the user is at least 18 years old,
// prove the user is from the EU but not from a Scandinavian country (note that Norway is not in the EU)
const {
  url,
  requestId,
  onQRCodeScanned,
  onGeneratingProof,
  onProofGenerated,
  onFinalResult,
  onReject,
  onError,
} = queryBuilder
  .disclose('firstname')
  .gte('age', 18)
  .in('nationality', EU_COUNTRIES)
  .out('nationality', ['Sweden', 'Denmark'])
  .done()

// Generate a url with the url and let your user scan it
// or transform it into a button if the user is on mobile

onQRCodeScanned(() => {
  // The user scanned the QR code or clicked the button
  // Essentially, this means the request popup is now opened
  // on the user phone
  console.log('QR code scanned')
})

onGeneratingProof(() => {
  // The user accepted the request and the proof is being generated
  console.log('Generating proof')
})

onProofGenerated(({ proof, vkeyHash }: ProofResult) => {
  // One of the proofs has been generated
  // You can retrieve the proof and the verification key hash (to be mapped to the actual vkey)
  // Note: the verify function will soon be added to the SDK so you can verify the proof
  // directly
  console.log('Proof generated', proof)
  console.log('Verification key hash', vkeyHash)
})

onFinalResult((result: QueryResult) => {
  // All the proofs have been generated and the final result is available
  console.log('firstname', result.firstname.disclose.result)
  console.log('age over 18', result.age.gte.result)
  console.log('nationality in EU', result.nationality.in.result)
  console.log('nationality not from Scandinavia', result.nationality.out.result)
  // You can also retrieved what were the values originally requested
  console.log('age over', result.age.gte.expected)
  console.log('nationality in', result.nationality.in.expected)
  console.log('nationality not in', result.nationality.out.expected)
})
```

### Using with Next.js

You can integrate `@zkpassport/sdk` into a Next.js application by creating a backend API route and calling it from your frontend.

#### **Backend (API Route)**

**App Router:** `app/api/zkpassport/route.ts`

```typescript
import { NextResponse } from 'next/server'
import { ZKPassport } from '@zkpassport/sdk'

export async function GET() {
  const zkPassport = new ZKPassport('demo.zkpassport.id') // Replace with your domain
  const queryBuilder = await zkPassport.request({
    name: 'ZKPassport Demo',
    logo: 'https://via.placeholder.com/150',
    purpose: 'Verify user nationality and first name',
  })
  const { url } = queryBuilder.disclose('nationality').disclose('firstname').done()
  return NextResponse.json({ url })
}
```

#### **Frontend Example**

**App Router:** `app/page.tsx`

```tsx
'use client'
import { useEffect, useState } from 'react'

export default function Home() {
  const [verificationUrl, setVerificationUrl] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/zkpassport')
      .then((res) => res.json())
      .then((data) => setVerificationUrl(data.url))
      .catch(console.error)
  }, [])

  return (
    <div>
      <h1>ZKPassport Demo</h1>
      {verificationUrl ? (
        <a href={verificationUrl} target="_blank" rel="noopener noreferrer">
          <button>Verify Identity</button>
        </a>
      ) : (
        <p>Loading...</p>
      )}
    </div>
  )
}
```

## Local installation

### Clone the repository

```sh
git clone https://github.com/zkpassport/zkpassport-sdk.git
cd zkpassport-sdk
```

### Install dependencies

```sh
bun install
```

### Run Tests

```sh
bun test
```

### Simulate Websocket Messages

Simulate mobile websocket messages: `bun run scripts/simulate.ts mobile`

Simulate frontend websocket messages: `bun run scripts/simulate.ts frontend`
