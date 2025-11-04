/**
 * Tipagem mínima para evitar erro "Cannot find module 'openapi-fetch'".
 * Você pode expandir estes tipos conforme precisar.
 */
declare module 'openapi-fetch' {
  export function createOpenAPIClient<T = any>(opts: { baseUrl?: string }): {
    // cliente genérico: métodos dependem do seu OpenAPI generator
    // retornamos `any` para flexibilidade; substitua por tipos mais precisos se quiser.
    request: (...args: any[]) => Promise<any>
  }

  export default createOpenAPIClient
}
