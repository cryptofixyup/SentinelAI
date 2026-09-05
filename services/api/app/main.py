from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.responses import HTMLResponse

from services.api.app.models import CheckTransactionRequest, CheckTransactionResponse
from services.intelligence.sentinel_risk.engine import (
    Confidence,
    Reputation,
    ReputationStatus,
    TransactionFacts,
    evaluate_transaction,
)

POLICY_VERSION = "day13-v3"

app = FastAPI(
    title="SentinelAI API",
    version="0.1.0",
    docs_url=None,  # Disable default docs to use custom ones with Speed Insights
    redoc_url=None,  # Disable default redoc to use custom ones with Speed Insights
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/check-tx", response_model=CheckTransactionResponse, tags=["risk"])
def check_transaction(request: CheckTransactionRequest) -> CheckTransactionResponse:
    tx = TransactionFacts(
        chain_id=request.chain_id,
        destination=request.destination,
        is_unlimited_approval=request.is_unlimited_approval,
        spender=request.spender,
    )
    destination_reputation = Reputation(
        status=ReputationStatus(request.destination_reputation.status),
        confidence=Confidence(request.destination_reputation.confidence),
    )
    spender_reputation = (
        Reputation(
            status=ReputationStatus(request.spender_reputation.status),
            confidence=Confidence(request.spender_reputation.confidence),
        )
        if request.spender_reputation
        else None
    )

    decision = evaluate_transaction(
        tx,
        destination_reputation,
        spender_reputation,
    )

    return CheckTransactionResponse(
        decision=decision.value,
        policy_version=POLICY_VERSION,
    )


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html() -> HTMLResponse:
    """
    Custom Swagger UI with Vercel Speed Insights integration.
    """
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} - Swagger UI",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        # Inject Vercel Speed Insights script
        swagger_ui_parameters={
            "persistAuthorization": True,
        },
    )
    # Inject Speed Insights script into the HTML
    html_content = html.body.decode()
    html_content = html_content.replace(
        "</head>",
        """<script>
  window.si = window.si || function () { (window.siq = window.siq || []).push(arguments); };
</script>
<script defer src="/_vercel/speed-insights/script.js"></script>
</head>""",
    )
    return HTMLResponse(content=html_content)


@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html() -> HTMLResponse:
    """
    Custom ReDoc with Vercel Speed Insights integration.
    """
    html = get_redoc_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} - ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )
    # Inject Speed Insights script into the HTML
    html_content = html.body.decode()
    html_content = html_content.replace(
        "</head>",
        """<script>
  window.si = window.si || function () { (window.siq = window.siq || []).push(arguments); };
</script>
<script defer src="/_vercel/speed-insights/script.js"></script>
</head>""",
    )
    return HTMLResponse(content=html_content)
