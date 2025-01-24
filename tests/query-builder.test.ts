import { ZKPassport as ZkPassportVerifier } from "../src/index"
import { MockWebSocket } from "./helpers/mock-websocket"

let wsClient: MockWebSocket | null = null
jest.mock("../src/websocket", () => {
  return {
    getWebSocketClient: jest.fn((url: string, origin?: string) => {
      const wsClientInstance = new MockWebSocket(url, {
        headers: {
          Origin: origin || "nodejs",
        },
      })
      wsClient = wsClientInstance
      return wsClientInstance
    }),
  }
})

describe("Query Builder", () => {
  let zkPassport: ZkPassportVerifier
  let queryBuilder: any

  beforeEach(async () => {
    zkPassport = new ZkPassportVerifier("localhost")
    queryBuilder = await zkPassport.request({
      name: "Test App",
      logo: "https://test.com/logo.png",
      purpose: "Testing query builder",
    })
  })

  afterEach(() => {
    wsClient!.close()
  })

  test("should build equality query with validation", async () => {
    const result = queryBuilder.eq("document_type", "passport").eq("gender", "F").done()

    expect(result.url).toContain("c=")
    const configPart = result.url.split("c=")[1].split("&")[0]
    const config = JSON.parse(Buffer.from(configPart, "base64").toString())

    // Test exact structure and values
    expect(config).toEqual({
      document_type: { eq: "passport" },
      gender: { eq: "F" },
    })

    // Test that no unexpected fields are present
    expect(Object.keys(config).length).toBe(2)
  })

  test("should build age comparison query with boundary validation", async () => {
    const result = queryBuilder.gte("age", 18).lt("age", 65).done()

    const configPart = result.url.split("c=")[1].split("&")[0]
    const config = JSON.parse(Buffer.from(configPart, "base64").toString())

    expect(config.age).toEqual({
      gte: 18,
      lt: 65,
    })
  })

  test("should build date range query with validation", async () => {
    const startDate = new Date("2024-01-01")
    const endDate = new Date("2024-12-31")
    const result = queryBuilder.range("birthdate", startDate, endDate).done()

    const configPart = result.url.split("c=")[1].split("&")[0]
    const config = JSON.parse(Buffer.from(configPart, "base64").toString())

    expect(config.birthdate.range).toEqual([startDate.toISOString(), endDate.toISOString()])
  })

  test("should build nationality inclusion/exclusion query with validation", async () => {
    const result = queryBuilder
      .in("nationality", ["FR", "DE", "IT"])
      .out("nationality", ["USA", "GB"])
      .done()

    const configPart = result.url.split("c=")[1].split("&")[0]
    const config = JSON.parse(Buffer.from(configPart, "base64").toString())

    expect(config.nationality).toEqual({
      in: ["FR", "DE", "IT"],
      out: ["USA", "GB"],
    })
  })

  test("should build disclosure request with validation", async () => {
    const result = queryBuilder.disclose("fullname").disclose("birthdate").done()

    const configPart = result.url.split("c=")[1].split("&")[0]
    const config = JSON.parse(Buffer.from(configPart, "base64").toString())

    expect(config).toEqual({
      fullname: { disclose: true },
      birthdate: { disclose: true },
    })
  })

  test("should combine multiple query types with complete validation", async () => {
    const startDate = new Date("2024-01-01")
    const result = queryBuilder
      .eq("document_type", "passport")
      .gte("age", 18)
      .in("nationality", ["FR", "DE"])
      .disclose("fullname")
      .range("expiry_date", startDate, new Date("2025-01-01"))
      .done()

    const configPart = result.url.split("c=")[1].split("&")[0]
    const config = JSON.parse(Buffer.from(configPart, "base64").toString())

    // Test complete structure
    expect(config).toEqual({
      document_type: { eq: "passport" },
      age: { gte: 18 },
      nationality: { in: ["FR", "DE"] },
      fullname: { disclose: true },
      expiry_date: { range: [startDate.toISOString(), new Date("2025-01-01").toISOString()] },
    })

    // Verify URL format
    expect(result.url).toMatch(
      /^https:\/\/zkpassport\.id\/r\?d=[^&]+&t=[^&]+&c=[A-Za-z0-9+/=]+&s=[A-Za-z0-9+/=]+&p=[^&]+$/,
    )

    // Verify service info is included
    const servicePart = result.url.split("s=")[1].split("&")[0]
    const service = JSON.parse(Buffer.from(servicePart, "base64").toString())
    expect(service).toEqual({
      name: "Test App",
      logo: "https://test.com/logo.png",
      purpose: "Testing query builder",
    })
  })
})
