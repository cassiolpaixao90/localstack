from aws_cdk import App, Stack, aws_sqs

app = App()
stack = Stack(app, "SynthStack")
aws_sqs.CfnQueue(stack, "Queue")
app.synth()
