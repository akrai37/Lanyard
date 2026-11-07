"""AWS Lambda entry point for the Lanyard gateway (served through a Lambda function URL)."""

from mangum import Mangum

from .gateway import app

handler = Mangum(app, lifespan="off")
