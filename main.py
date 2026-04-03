"""AgenticTM — Quick start entry point."""

from agentictm.core import AgenticTM


def main():
    """Ejemplo de uso programático."""
    tm = AgenticTM()

    # Ejemplo: analizar un sistema descrito en texto
    result = tm.analyze(
        system_input="""
        Sistema de e-commerce con:
        - Frontend React en Vercel (público)
        - API Gateway (Kong) en AWS
        - 3 microservicios (auth, catalog, orders) en EKS
        - PostgreSQL RDS para datos de usuarios y órdenes
        - Redis ElastiCache para sesiones
        - S3 para imágenes de productos
        - Stripe API para pagos
        - SendGrid para emails
        """,
        system_name="E-Commerce Platform",
    )

    # Guardar outputs
    output_path = tm.save_output(result)
    print(f"Output guardado en: {output_path}")

    # Acceder a los resultados
    for threat in result.get("threats_final", []):
        print(f"  [{threat['priority']}] {threat['id']}: {threat['description'][:60]}...")


if __name__ == "__main__":
    main()
