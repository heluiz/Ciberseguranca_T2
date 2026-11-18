// Documentação interativa da API v1 (Swagger UI), a partir do contrato
// OpenAPI do repositório (docs/web/openapi.yaml).
window.addEventListener('load', () => {
  window.ui = SwaggerUIBundle({
    url: '/api/v1/openapi.yaml',
    dom_id: '#swagger-ui',
    deepLinking: false,
    persistAuthorization: false,
    tryItOutEnabled: false,
  });
});
