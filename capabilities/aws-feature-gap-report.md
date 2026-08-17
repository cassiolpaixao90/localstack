# Relatorio completo de lacunas AWS e AWS CDK

> Arquivo gerado. Nao edite manualmente. Inventario estatico identifica caminhos candidatos; nao comprova paridade com a AWS.

## Veredito executivo

O checkout ainda nao oferece todas as features AWS. A maior parte do denominador Botocore nao possui caminho de implementacao neste repositorio, e nenhum operation status foi promovido para `native` ou `parity-pass` por evidencia runtime diferencial.

- **15,932 de 18,993 operacoes (83.88%)** estao `missing`.
- **3,061 operacoes (16.12%)** possuem somente algum caminho estatico (`scaffold`, fallback ou provider parcial).
- **41 de 429 servicos** possuem algum caminho estatico; 388 estao integralmente ausentes no inventario local.
- **126 de 1,557 recursos CDK L1 (8.09%)** resolvem para um resource provider LocalStack registrado.
- O mapa CDK tem 8 namespaces estaticamente completos, 21 parciais e 243 sem provider registrado.
- Dos **425 handlers declarados** nos schemas dos providers CDK, somente **250** possuem corpo direto sem `NotImplementedError` detectavel; isso continua sem comprovar comportamento.
- `available` no endpoint de health significa que o servico foi carregado; nao significa cobertura total, CRUD completo, rollback correto ou paridade AWS.

## Fontes content-addressed

| Fonte | Versao/claim | SHA-256 dos bytes | Digest semantico |
|---|---|---|---|
| `capabilities/generated/capabilities.json` | Botocore `1.43.67` | `sha256:7c754a65e0eefce0fe5c41764cd76a6f7b62de01a81909a721e073a44e002ed5` | `sha256:1a44df47d6c1450fd214472599d3d9f96a12edde9ea30a9c8b21fac31eae9a54` |
| `capabilities/cdk/services.json` | aws-cdk-lib `2.241.0` / `static-inventory-only` | `sha256:91cdc4a33e32a1669a0b9f4abd734d36a4d04d017ad56e4c2074be4822e5cfd1` | `sha256:1e34b61cfb5354b6de9c5da71966f624d0410cb4e630f850ded8923187e16d2f` |
| `capabilities/cdk/compatibility.json` | schema `2` | `sha256:26e24331c65249450c4eaa019c55abfdb918795b90802c5bb3c98acf95847605` | `sha256:786dd38252a62f68607d668bc2dc7559ba691bec6fd4def967f383e18c7e0193` |

## Lacunas de operacoes AWS

| Status | Quantidade | Percentual | Interpretacao |
|---|---:|---:|---|
| `missing` | 15,932 | 83.88% | Sem interface/provider classificado neste checkout |
| `scaffold` | 286 | 1.51% | Handler gerado sem implementacao ou fallback |
| `fallback` | 1,939 | 10.21% | Delegacao Moto/HTTP; comportamento e estado podem divergir |
| `partial` | 836 | 4.40% | Override existe, mas runtime/paridade nao foram promovidos |
| `native` | 0 | 0.00% | Exige evidencia runtime nativa |
| `parity-pass` | 0 | 0.00% | Exige diferencial AWS recente e sem exclusoes criticas |

### Distribuicao dos servicos pelo melhor nivel encontrado

| Melhor nivel estatico | Servicos |
|---|---:|
| `fully-missing` | 388 |
| `scaffold` | 2 |
| `fallback` | 10 |
| `partial` | 29 |
| `native` | 0 |
| `parity-pass` | 0 |

## CloudFormation e AWS CDK

- Modulos CDK inventariados: **300**.
- Modulos com L1: **272**; modulos auxiliares/L2 sem L1 proprio: **28**.
- Tipos CDK L1: **1,557**.
- Tipos no catalogo CloudFormation local: **1,555**.
- Intersecao CDK/catalogo CFN: **1,544**.
- Tipos CDK ausentes do catalogo CFN local: **13**.
- Tipos CFN locais ausentes do aws-cdk-lib pinado: **11**.
- Modulos L1 sem candidato de API: **18**.
- Providers CDK cujos handlers declarados possuem todos os corpos presentes (nao verificados): **27**; com superficie estatica incompleta: **62**; sem declaracoes de handlers no schema: **37**.
- Lacunas de handler declaradas: **97** stubs exatos, **1** corpo parcial contendo `NotImplementedError` e **77** metodos ausentes.

### Drift de tipos

**Somente no CDK pinado:**

`AWS::IoTFleetHub::Application`<br>`AWS::LookoutMetrics::Alert`<br>`AWS::LookoutMetrics::AnomalyDetector`<br>`AWS::NimbleStudio::LaunchProfile`<br>`AWS::NimbleStudio::StreamingImage`<br>`AWS::NimbleStudio::StudioComponent`<br>`AWS::Serverless::Api`<br>`AWS::Serverless::Application`<br>`AWS::Serverless::Function`<br>`AWS::Serverless::HttpApi`<br>`AWS::Serverless::LayerVersion`<br>`AWS::Serverless::SimpleTable`<br>`AWS::Serverless::StateMachine`

**Somente no catalogo CloudFormation local:**

`AMZN::SDC::Deployment`<br>`AWS::BedrockAgentCore::BrowserProfile`<br>`AWS::BedrockAgentCore::Evaluator`<br>`AWS::BedrockAgentCore::OnlineEvaluationConfig`<br>`AWS::BedrockMantle::Project`<br>`AWS::Billing::BillingView`<br>`AWS::GammaDilithium::JobDefinition`<br>`AWS::IoTManagedIntegrations::CredentialLocker`<br>`AWS::IoTManagedIntegrations::ManagedThing`<br>`AWS::IoTManagedIntegrations::ProvisioningProfile`<br>`AWS::Lambda::ResourcePolicy`

### Namespaces CDK ainda sem candidato de API

| Modulo | Namespaces CFN sem mapeamento | L1s |
|---|---|---:|
| `alexa_ask` | `ASK` | 1 |
| `aws_apptest` | `AppTest` | 1 |
| `aws_codestar` | `CodeStar` | 1 |
| `aws_evidently` | `Evidently` | 5 |
| `aws_iotanalytics` | `IoTAnalytics` | 4 |
| `aws_iotevents` | `IoTEvents` | 3 |
| `aws_iotfleethub` | `IoTFleetHub` | 1 |
| `aws_lookoutmetrics` | `LookoutMetrics` | 2 |
| `aws_lookoutvision` | `LookoutVision` | 1 |
| `aws_nimblestudio` | `NimbleStudio` | 4 |
| `aws_opsworks` | `OpsWorks` | 7 |
| `aws_opsworkscm` | `OpsWorksCM` | 1 |
| `aws_panorama` | `Panorama` | 3 |
| `aws_qldb` | `QLDB` | 2 |
| `aws_robomaker` | `RoboMaker` | 6 |
| `aws_s3express` | `S3Express` | 3 |
| `aws_sam` | `Serverless` | 7 |
| `aws_simspaceweaver` | `SimSpaceWeaver` | 1 |

## Evidencia CDK atual

### Cenarios reais de CLI retidos

| Cenario | Status | Linguagem | Plataformas | Limitacoes |
|---|---|---|---|---|
| `bootstrap-show-template-v32` | `cli-pass` | `language-neutral` | `linux-amd64`<br>`linux-arm64` | `no-bootstrap-deploy`<br>`no-cloud-assembly`<br>`no-language-binding`<br>`no-aws-differential` |
| `bootstrap-upgrade-v28-v32` | `cli-pass` | `language-neutral` | `linux-amd64`<br>`linux-arm64` | `no-clean-bootstrap-create`<br>`no-cloud-assembly`<br>`no-language-binding`<br>`no-aws-differential` |

### Matriz de capacidades CDK

| Capacidade | Status | Linguagens | Lacunas declaradas |
|---|---|---|---|
| `bootstrap` | `api-simulated` | - | `clean-bootstrap-create-cli-not-run`<br>`validation-stale` |
| `context-lookups` | `untested` | - | `real-cli-not-run` |
| `custom-resources` | `untested` | - | `transparent-endpoint-injection-not-validated` |
| `deploy` | `api-simulated` | `python` | `real-cli-not-run` |
| `destroy` | `api-simulated` | `python` | `real-cli-not-run` |
| `diff` | `untested` | - | `real-cli-not-run` |
| `docker-assets` | `blocked` | - | `bootstrapless-synthesizer`<br>`images-loaded-manually` |
| `file-assets` | `blocked` | - | `bootstrapless-synthesizer`<br>`assets-loaded-manually` |
| `hotswap` | `untested` | - | `real-cli-not-run` |
| `init` | `untested` | - | `real-cli-not-run` |
| `list` | `untested` | - | `real-cli-not-run` |
| `nested-stacks` | `untested` | - | `real-cli-not-run` |
| `no-op` | `api-simulated` | `python` | `waiter-error-is-treated-as-no-op` |
| `synth` | `template-api-only` | `python` | `cloud-assembly-not-produced`<br>`real-cli-not-run` |
| `transforms` | `untested` | - | `no-transform-template-in-current-cdk-corpus` |
| `update` | `api-simulated` | `python` | `no-explicit-update-scenario`<br>`real-cli-not-run` |

## Backlog recomendado

1. **Converter presenca estatica em evidencia lifecycle:** create/read/update/no-op/delete, rollback, falha parcial e cleanup para os 8 namespaces CDK estaticamente completos.
2. **Fechar os menores gaps de resource providers:** priorizar modulos parciais com um ou dois tipos ausentes e APIs locais ja mapeadas.
3. **Reduzir fallback:** substituir caminhos Moto/HTTP onde ownership, idempotencia ou consistencia diferem da AWS.
4. **Abrir os servicos integralmente ausentes:** priorizar demanda real e dependencias centrais; nao usar apenas contagem bruta de operacoes.
5. **Produzir evidencia AWS diferencial:** nenhum status pode virar `parity-pass` sem run AWS recente, JUnit exato, proveniencia e cleanup comprovado.
6. **Manter packaging honesto:** uma imagem sem filtro de servicos nao implementa codigo que nao existe neste checkout e nao deve ser rotulada como feature-complete apenas pelo nome da tag.

### Modulos CDK estaticamente completos que ainda precisam de evidencia runtime

| Modulo | L1s | APIs candidatas |
|---|---:|---|
| `aws_cognito` | 16 | `cognito-identity`<br>`cognito-idp`<br>`cognito-sync` |
| `aws_dynamodb` | 2 | `dynamodb` |
| `aws_elasticsearch` | 1 | `opensearch` |
| `aws_kinesisfirehose` | 1 | `firehose` |
| `aws_scheduler` | 2 | `scheduler` |
| `aws_secretsmanager` | 4 | `secretsmanager` |
| `aws_sns` | 4 | `sns` |
| `aws_sqs` | 3 | `sqs` |

### Modulos CDK parciais ordenados pelo menor gap

| Modulo | Providers/L1s | Faltantes | Tipos faltantes |
|---|---:|---:|---|
| `aws_certificatemanager` | 1/2 | 1 | `AWS::CertificateManager::Account` |
| `aws_kinesis` | 2/3 | 1 | `AWS::Kinesis::ResourcePolicy` |
| `aws_kms` | 2/3 | 1 | `AWS::KMS::ReplicaKey` |
| `aws_lambda` | 10/11 | 1 | `AWS::Lambda::CapacityProvider` |
| `aws_opensearchservice` | 1/2 | 1 | `AWS::OpenSearchService::Application` |
| `aws_resourcegroups` | 1/2 | 1 | `AWS::ResourceGroups::TagSyncTask` |
| `aws_events` | 5/7 | 2 | `AWS::Events::Archive`<br>`AWS::Events::Endpoint` |
| `aws_stepfunctions` | 2/4 | 2 | `AWS::StepFunctions::StateMachineAlias`<br>`AWS::StepFunctions::StateMachineVersion` |
| `aws_ssm` | 5/9 | 4 | `AWS::SSM::Association`<br>`AWS::SSM::Document`<br>`AWS::SSM::ResourceDataSync`<br>`AWS::SSM::ResourcePolicy` |
| `aws_cloudwatch` | 2/7 | 5 | `AWS::CloudWatch::AlarmMuteRule`<br>`AWS::CloudWatch::AnomalyDetector`<br>`AWS::CloudWatch::Dashboard`<br>`AWS::CloudWatch::InsightRule`<br>`AWS::CloudWatch::MetricStream` |
| `aws_route53` | 2/7 | 5 | `AWS::Route53::CidrCollection`<br>`AWS::Route53::DNSSEC`<br>`AWS::Route53::HostedZone`<br>`AWS::Route53::KeySigningKey`<br>`AWS::Route53::RecordSetGroup` |
| `aws_apigatewayv2` | 8/14 | 6 | `AWS::ApiGatewayV2::ApiGatewayManagedOverrides`<br>`AWS::ApiGatewayV2::IntegrationResponse`<br>`AWS::ApiGatewayV2::Model`<br>`AWS::ApiGatewayV2::RouteResponse`<br>`AWS::ApiGatewayV2::RoutingRule`<br>`AWS::ApiGatewayV2::VpcLink` |
| `aws_iam` | 9/16 | 7 | `AWS::IAM::GroupPolicy`<br>`AWS::IAM::OIDCProvider`<br>`AWS::IAM::RolePolicy`<br>`AWS::IAM::SAMLProvider`<br>`AWS::IAM::UserPolicy`<br>`AWS::IAM::UserToGroupAddition`<br>`AWS::IAM::VirtualMFADevice` |
| `aws_apigateway` | 14/22 | 8 | `AWS::ApiGateway::Authorizer`<br>`AWS::ApiGateway::BasePathMappingV2`<br>`AWS::ApiGateway::ClientCertificate`<br>`AWS::ApiGateway::DocumentationPart`<br>`AWS::ApiGateway::DocumentationVersion`<br>`AWS::ApiGateway::DomainNameAccessAssociation`<br>`AWS::ApiGateway::DomainNameV2`<br>`AWS::ApiGateway::VpcLink` |
| `aws_ecr` | 1/9 | 8 | `AWS::ECR::PublicRepository`<br>`AWS::ECR::PullThroughCacheRule`<br>`AWS::ECR::PullTimeUpdateExclusion`<br>`AWS::ECR::RegistryPolicy`<br>`AWS::ECR::RegistryScanningConfiguration`<br>`AWS::ECR::ReplicationConfiguration`<br>`AWS::ECR::RepositoryCreationTemplate`<br>`AWS::ECR::SigningConfiguration` |
| `aws_s3` | 2/10 | 8 | `AWS::S3::AccessGrant`<br>`AWS::S3::AccessGrantsInstance`<br>`AWS::S3::AccessGrantsLocation`<br>`AWS::S3::AccessPoint`<br>`AWS::S3::MultiRegionAccessPoint`<br>`AWS::S3::MultiRegionAccessPointPolicy`<br>`AWS::S3::StorageLens`<br>`AWS::S3::StorageLensGroup` |
| `aws_redshift` | 1/10 | 9 | `AWS::Redshift::ClusterParameterGroup`<br>`AWS::Redshift::ClusterSecurityGroup`<br>`AWS::Redshift::ClusterSecurityGroupIngress`<br>`AWS::Redshift::ClusterSubnetGroup`<br>`AWS::Redshift::EndpointAccess`<br>`AWS::Redshift::EndpointAuthorization`<br>`AWS::Redshift::EventSubscription`<br>`AWS::Redshift::Integration`<br>`AWS::Redshift::ScheduledAction` |
| `aws_logs` | 3/15 | 12 | `AWS::Logs::AccountPolicy`<br>`AWS::Logs::Delivery`<br>`AWS::Logs::DeliveryDestination`<br>`AWS::Logs::DeliverySource`<br>`AWS::Logs::Destination`<br>`AWS::Logs::Integration`<br>`AWS::Logs::LogAnomalyDetector`<br>`AWS::Logs::MetricFilter`<br>`AWS::Logs::QueryDefinition`<br>`AWS::Logs::ResourcePolicy`<br>`AWS::Logs::ScheduledQuery`<br>`AWS::Logs::Transformer` |
| `aws_cloudformation` | 4/18 | 14 | `AWS::CloudFormation::CustomResource`<br>`AWS::CloudFormation::GuardHook`<br>`AWS::CloudFormation::HookDefaultVersion`<br>`AWS::CloudFormation::HookTypeConfig`<br>`AWS::CloudFormation::HookVersion`<br>`AWS::CloudFormation::LambdaHook`<br>`AWS::CloudFormation::ModuleDefaultVersion`<br>`AWS::CloudFormation::ModuleVersion`<br>`AWS::CloudFormation::PublicTypeVersion`<br>`AWS::CloudFormation::Publisher`<br>`AWS::CloudFormation::ResourceDefaultVersion`<br>`AWS::CloudFormation::ResourceVersion`<br>`AWS::CloudFormation::StackSet`<br>`AWS::CloudFormation::TypeActivation` |
| `aws_ses` | 1/21 | 20 | `AWS::SES::ConfigurationSet`<br>`AWS::SES::ConfigurationSetEventDestination`<br>`AWS::SES::ContactList`<br>`AWS::SES::CustomVerificationEmailTemplate`<br>`AWS::SES::DedicatedIpPool`<br>`AWS::SES::MailManagerAddonInstance`<br>`AWS::SES::MailManagerAddonSubscription`<br>`AWS::SES::MailManagerAddressList`<br>`AWS::SES::MailManagerArchive`<br>`AWS::SES::MailManagerIngressPoint`<br>`AWS::SES::MailManagerRelay`<br>`AWS::SES::MailManagerRuleSet`<br>`AWS::SES::MailManagerTrafficPolicy`<br>`AWS::SES::MultiRegionEndpoint`<br>`AWS::SES::ReceiptFilter`<br>`AWS::SES::ReceiptRule`<br>`AWS::SES::ReceiptRuleSet`<br>`AWS::SES::Template`<br>`AWS::SES::Tenant`<br>`AWS::SES::VdmAttributes` |
| `aws_ec2` | 17/111 | 94 | `AWS::EC2::CapacityManagerDataExport`<br>`AWS::EC2::CapacityReservation`<br>`AWS::EC2::CapacityReservationFleet`<br>`AWS::EC2::CarrierGateway`<br>`AWS::EC2::ClientVpnAuthorizationRule`<br>`AWS::EC2::ClientVpnEndpoint`<br>`AWS::EC2::ClientVpnRoute`<br>`AWS::EC2::ClientVpnTargetNetworkAssociation`<br>`AWS::EC2::CustomerGateway`<br>`AWS::EC2::EC2Fleet`<br>`AWS::EC2::EIP`<br>`AWS::EC2::EIPAssociation`<br>`AWS::EC2::EgressOnlyInternetGateway`<br>`AWS::EC2::EnclaveCertificateIamRoleAssociation`<br>`AWS::EC2::FlowLog`<br>`AWS::EC2::GatewayRouteTableAssociation`<br>`AWS::EC2::Host`<br>`AWS::EC2::IPAM`<br>`AWS::EC2::IPAMAllocation`<br>`AWS::EC2::IPAMPool`<br>`AWS::EC2::IPAMPoolCidr`<br>`AWS::EC2::IPAMPrefixListResolver`<br>`AWS::EC2::IPAMResourceDiscovery`<br>`AWS::EC2::IPAMResourceDiscoveryAssociation`<br>`AWS::EC2::IPAMScope`<br>`AWS::EC2::InstanceConnectEndpoint`<br>`AWS::EC2::IpPoolRouteTableAssociation`<br>`AWS::EC2::LaunchTemplate`<br>`AWS::EC2::LocalGatewayRoute`<br>`AWS::EC2::LocalGatewayRouteTable`<br>`AWS::EC2::LocalGatewayRouteTableVPCAssociation`<br>`AWS::EC2::LocalGatewayRouteTableVirtualInterfaceGroupAssociation`<br>`AWS::EC2::LocalGatewayVirtualInterface`<br>`AWS::EC2::LocalGatewayVirtualInterfaceGroup`<br>`AWS::EC2::NetworkAclEntry`<br>`AWS::EC2::NetworkInsightsAccessScope`<br>`AWS::EC2::NetworkInsightsAccessScopeAnalysis`<br>`AWS::EC2::NetworkInsightsAnalysis`<br>`AWS::EC2::NetworkInsightsPath`<br>`AWS::EC2::NetworkInterface`<br>`AWS::EC2::NetworkInterfaceAttachment`<br>`AWS::EC2::NetworkInterfacePermission`<br>`AWS::EC2::NetworkPerformanceMetricSubscription`<br>`AWS::EC2::PlacementGroup`<br>`AWS::EC2::RouteServer`<br>`AWS::EC2::RouteServerAssociation`<br>`AWS::EC2::RouteServerEndpoint`<br>`AWS::EC2::RouteServerPeer`<br>`AWS::EC2::RouteServerPropagation`<br>`AWS::EC2::SecurityGroupEgress`<br>`AWS::EC2::SecurityGroupIngress`<br>`AWS::EC2::SecurityGroupVpcAssociation`<br>`AWS::EC2::SnapshotBlockPublicAccess`<br>`AWS::EC2::SpotFleet`<br>`AWS::EC2::SubnetCidrBlock`<br>`AWS::EC2::SubnetNetworkAclAssociation`<br>`AWS::EC2::TrafficMirrorFilter`<br>`AWS::EC2::TrafficMirrorFilterRule`<br>`AWS::EC2::TrafficMirrorSession`<br>`AWS::EC2::TrafficMirrorTarget`<br>`AWS::EC2::TransitGatewayConnect`<br>`AWS::EC2::TransitGatewayConnectPeer`<br>`AWS::EC2::TransitGatewayMeteringPolicy`<br>`AWS::EC2::TransitGatewayMeteringPolicyEntry`<br>`AWS::EC2::TransitGatewayMulticastDomain`<br>`AWS::EC2::TransitGatewayMulticastDomainAssociation`<br>`AWS::EC2::TransitGatewayMulticastGroupMember`<br>`AWS::EC2::TransitGatewayMulticastGroupSource`<br>`AWS::EC2::TransitGatewayPeeringAttachment`<br>`AWS::EC2::TransitGatewayRoute`<br>`AWS::EC2::TransitGatewayRouteTable`<br>`AWS::EC2::TransitGatewayRouteTableAssociation`<br>`AWS::EC2::TransitGatewayRouteTablePropagation`<br>`AWS::EC2::TransitGatewayVpcAttachment`<br>`AWS::EC2::VPCBlockPublicAccessExclusion`<br>`AWS::EC2::VPCBlockPublicAccessOptions`<br>`AWS::EC2::VPCCidrBlock`<br>`AWS::EC2::VPCDHCPOptionsAssociation`<br>`AWS::EC2::VPCEncryptionControl`<br>`AWS::EC2::VPCEndpointConnectionNotification`<br>`AWS::EC2::VPCEndpointService`<br>`AWS::EC2::VPCEndpointServicePermissions`<br>`AWS::EC2::VPCPeeringConnection`<br>`AWS::EC2::VPNConcentrator`<br>`AWS::EC2::VPNConnection`<br>`AWS::EC2::VPNConnectionRoute`<br>`AWS::EC2::VPNGateway`<br>`AWS::EC2::VPNGatewayRoutePropagation`<br>`AWS::EC2::VerifiedAccessEndpoint`<br>`AWS::EC2::VerifiedAccessGroup`<br>`AWS::EC2::VerifiedAccessInstance`<br>`AWS::EC2::VerifiedAccessTrustProvider`<br>`AWS::EC2::Volume`<br>`AWS::EC2::VolumeAttachment` |

## Anexo A — todos os servicos e operacoes por status

A tabela cobre todos os servicos do Botocore pinado. Os nomes exatos das operacoes em cada grupo estao em `capabilities/generated/capabilities.json` em `/services/<service>/operation_statuses`; o relatorio nao duplica 17.854 nomes para permanecer revisavel.

| Servico | Ops | Missing | Scaffold | Fallback | Partial | Native | Parity | Provider | CFN |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| `accessanalyzer` | 39 | 39 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `account` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `acm` | 39 | 23 | 0 | 16 | 0 | 0 | 0 | `default` | 1 |
| `acm-pca` | 23 | 23 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `agent-registry` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `agent-registry-control` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `aiops` | 11 | 11 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `amp` | 44 | 44 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `amplify` | 37 | 37 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `amplifybackend` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `amplifyuibuilder` | 28 | 28 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `apigateway` | 124 | 0 | 0 | 50 | 74 | 0 | 0 | `default` | 14 |
| `apigatewaymanagementapi` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `apigatewayv2` | 103 | 61 | 0 | 0 | 42 | 0 | 0 | `default` | 8 |
| `appconfig` | 56 | 56 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `appconfigdata` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `appfabric` | 26 | 26 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `appflow` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `appintegrations` | 23 | 23 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `application-autoscaling` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `application-insights` | 33 | 33 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `application-signals` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `applicationcostprofiler` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `appmesh` | 38 | 38 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `apprunner` | 37 | 37 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `appstream` | 89 | 89 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `appsync` | 74 | 74 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `arc-region-switch` | 21 | 21 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `arc-zonal-shift` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `artifact` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `athena` | 70 | 70 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `auditmanager` | 62 | 62 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `autoscaling` | 66 | 66 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `autoscaling-plans` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `b2bi` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `backup` | 115 | 115 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `backup-gateway` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `backupsearch` | 12 | 12 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `batch` | 45 | 45 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bcm-dashboards` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bcm-data-exports` | 12 | 12 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bcm-pricing-calculator` | 36 | 36 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bcm-recommended-actions` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock` | 108 | 108 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock-agent` | 75 | 75 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock-agent-runtime` | 33 | 33 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock-agentcore` | 66 | 66 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock-agentcore-control` | 165 | 165 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock-data-automation` | 27 | 27 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock-data-automation-runtime` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `bedrock-runtime` | 11 | 11 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `billing` | 20 | 20 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `billingconductor` | 32 | 32 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `braket` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `budgets` | 26 | 26 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ce` | 47 | 47 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `chatbot` | 34 | 34 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `chime` | 62 | 62 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `chime-sdk-identity` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `chime-sdk-media-pipelines` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `chime-sdk-meetings` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `chime-sdk-messaging` | 51 | 51 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `chime-sdk-voice` | 96 | 96 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cleanrooms` | 100 | 100 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cleanroomsml` | 59 | 59 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloud9` | 13 | 13 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudcontrol` | 8 | 0 | 8 | 0 | 0 | 0 | 0 | `-` | 0 |
| `clouddirectory` | 66 | 66 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudformation` | 90 | 0 | 59 | 0 | 31 | 0 | 0 | `default` | 4 |
| `cloudfront` | 167 | 167 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudfront-keyvaluestore` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudhsm` | 20 | 20 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudhsmv2` | 18 | 18 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudsearch` | 26 | 26 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudsearchdomain` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudtrail` | 60 | 60 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudtrail-data` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cloudwatch` | 50 | 7 | 23 | 0 | 20 | 0 | 0 | `default` | 2 |
| `codeartifact` | 48 | 48 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codebuild` | 59 | 59 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codecatalyst` | 38 | 38 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codecommit` | 79 | 79 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codeconnections` | 27 | 27 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codedeploy` | 47 | 47 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codeguru-reviewer` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codeguru-security` | 13 | 13 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codeguruprofiler` | 23 | 23 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codepipeline` | 44 | 44 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codestar-connections` | 27 | 27 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `codestar-notifications` | 13 | 13 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cognito-identity` | 23 | 0 | 0 | 0 | 23 | 0 | 0 | `default` | 3 |
| `cognito-idp` | 129 | 0 | 0 | 0 | 129 | 0 | 0 | `default` | 15 |
| `cognito-sync` | 17 | 0 | 0 | 0 | 17 | 0 | 0 | `default` | 0 |
| `comprehend` | 85 | 85 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `comprehendmedical` | 26 | 26 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `compute-optimizer` | 28 | 28 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `compute-optimizer-automation` | 23 | 23 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `config` | 102 | 5 | 0 | 97 | 0 | 0 | 0 | `default` | 0 |
| `connect` | 380 | 380 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `connect-contact-lens` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `connectcampaigns` | 22 | 22 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `connectcampaignsv2` | 37 | 37 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `connectcases` | 43 | 43 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `connecthealth` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `connectparticipant` | 11 | 11 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `controlcatalog` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `controltower` | 28 | 28 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cost-optimization-hub` | 8 | 8 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `cur` | 7 | 7 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `customer-profiles` | 107 | 107 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `databrew` | 44 | 44 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `dataexchange` | 37 | 37 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `datapipeline` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `datasync` | 53 | 53 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `datazone` | 190 | 190 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `dax` | 21 | 21 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `deadline` | 126 | 126 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `detective` | 29 | 29 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `devicefarm` | 77 | 77 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `devops-agent` | 62 | 62 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `devops-guru` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `directconnect` | 64 | 64 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `discovery` | 28 | 28 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `dlm` | 8 | 8 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `dms` | 119 | 119 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `docdb` | 55 | 55 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `docdb-elastic` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `drs` | 50 | 50 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ds` | 80 | 80 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ds-data` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `dsql` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `dynamodb` | 58 | 1 | 0 | 23 | 34 | 0 | 0 | `default` | 2 |
| `dynamodbstreams` | 4 | 0 | 0 | 0 | 4 | 0 | 0 | `default` | 0 |
| `ebs` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ec2` | 800 | 44 | 0 | 750 | 6 | 0 | 0 | `default` | 17 |
| `ec2-instance-connect` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ecr` | 58 | 58 | 0 | 0 | 0 | 0 | 0 | `-` | 1 |
| `ecr-public` | 23 | 23 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ecs` | 77 | 77 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `efs` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `eks` | 65 | 65 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `eks-auth` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `elasticache` | 75 | 75 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `elasticbeanstalk` | 47 | 47 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `elb` | 29 | 29 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `elbv2` | 51 | 51 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `elementalinference` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `emr` | 65 | 65 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `emr-containers` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `emr-serverless` | 22 | 22 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `entityresolution` | 38 | 38 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `es` | 51 | 0 | 39 | 0 | 12 | 0 | 0 | `default` | 0 |
| `events` | 57 | 0 | 17 | 0 | 40 | 0 | 0 | `default` | 5 |
| `evs` | 22 | 22 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `finspace` | 50 | 50 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `finspace-data` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `firehose` | 12 | 0 | 2 | 0 | 10 | 0 | 0 | `default` | 1 |
| `fis` | 26 | 26 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `fms` | 42 | 42 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `forecast` | 63 | 63 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `forecastquery` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `frauddetector` | 73 | 73 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `freetier` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `fsx` | 48 | 48 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `gamelift` | 120 | 120 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `gameliftstreams` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `geo-maps` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `geo-places` | 7 | 7 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `geo-routes` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `glacier` | 33 | 33 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `globalaccelerator` | 56 | 56 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `glue` | 299 | 299 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `grafana` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `greengrass` | 92 | 92 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `greengrassv2` | 29 | 29 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `groundstation` | 40 | 40 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `guardduty` | 90 | 90 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `health` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `healthlake` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iam` | 176 | 0 | 0 | 158 | 18 | 0 | 0 | `default` | 9 |
| `identitystore` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `imagebuilder` | 77 | 77 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `importexport` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `inspector` | 37 | 37 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `inspector-scan` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `inspector2` | 81 | 81 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `interconnect` | 13 | 13 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `internetmonitor` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `invoicing` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iot` | 272 | 272 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iot-data` | 11 | 11 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iot-jobs-data` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iot-managed-integrations` | 83 | 83 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iotdeviceadvisor` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iotfleetwise` | 57 | 57 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iotsecuretunneling` | 8 | 8 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iotsitewise` | 149 | 149 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iotthingsgraph` | 35 | 35 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iottwinmaker` | 40 | 40 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `iotwireless` | 112 | 112 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ivs` | 41 | 41 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ivs-realtime` | 39 | 39 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ivschat` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kafka` | 64 | 64 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kafkaconnect` | 18 | 18 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kendra` | 66 | 66 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kendra-ranking` | 9 | 9 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `keyspaces` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `keyspacesstreams` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kinesis` | 39 | 0 | 0 | 33 | 6 | 0 | 0 | `default` | 2 |
| `kinesis-video-archived-media` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kinesis-video-media` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kinesis-video-signaling` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kinesis-video-webrtc-storage` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kinesisanalytics` | 20 | 20 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kinesisanalyticsv2` | 33 | 33 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kinesisvideo` | 32 | 32 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `kms` | 54 | 1 | 8 | 0 | 45 | 0 | 0 | `default` | 2 |
| `lakeformation` | 61 | 61 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `lambda` | 85 | 0 | 21 | 0 | 64 | 0 | 0 | `default` | 10 |
| `lambda-core` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `lambda-microvms` | 24 | 24 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `launch-wizard` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `lex-models` | 42 | 42 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `lex-runtime` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `lexv2-models` | 107 | 107 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `lexv2-runtime` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `license-manager` | 62 | 62 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `license-manager-linux-subscriptions` | 11 | 11 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `license-manager-user-subscriptions` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `lightsail` | 161 | 161 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `location` | 64 | 64 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `logs` | 118 | 11 | 0 | 99 | 8 | 0 | 0 | `default` | 3 |
| `lookoutequipment` | 49 | 49 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `m2` | 37 | 37 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `machinelearning` | 28 | 28 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `macie2` | 81 | 81 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mailmanager` | 60 | 60 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `managedblockchain` | 27 | 27 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `managedblockchain-query` | 9 | 9 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `marketplace-agreement` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `marketplace-catalog` | 13 | 13 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `marketplace-deployment` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `marketplace-discovery` | 9 | 9 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `marketplace-entitlement` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `marketplace-reporting` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `marketplacecommerceanalytics` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediaconnect` | 82 | 82 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediaconvert` | 34 | 34 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `medialive` | 123 | 123 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediapackage` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediapackage-vod` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediapackagev2` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediastore` | 21 | 21 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediastore-data` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mediatailor` | 48 | 48 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `medical-imaging` | 18 | 18 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `memorydb` | 45 | 45 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `meteringmarketplace` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mgh` | 21 | 21 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mgn` | 95 | 95 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `migration-hub-refactor-spaces` | 24 | 24 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `migrationhub-config` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `migrationhuborchestrator` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `migrationhubstrategy` | 22 | 22 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mpa` | 22 | 22 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mq` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mturk` | 39 | 39 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mwaa` | 12 | 12 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `mwaa-serverless` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `neptune` | 70 | 70 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `neptune-graph` | 34 | 34 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `neptunedata` | 43 | 43 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `network-firewall` | 85 | 85 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `networkflowmonitor` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `networkmanager` | 95 | 95 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `networkmonitor` | 12 | 12 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `notifications` | 39 | 39 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `notificationscontacts` | 9 | 9 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `nova-act` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `oam` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `observabilityadmin` | 40 | 40 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `odb` | 66 | 66 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `omics` | 107 | 107 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `opensearch` | 96 | 14 | 70 | 0 | 12 | 0 | 0 | `default` | 2 |
| `opensearchserverless` | 46 | 46 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `organizations` | 63 | 63 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `osis` | 22 | 22 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `outposts` | 43 | 43 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `partnercentral-account` | 34 | 34 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `partnercentral-benefits` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `partnercentral-channel` | 17 | 17 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `partnercentral-revenue-measurement` | 18 | 18 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `partnercentral-selling` | 45 | 45 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `payment-cryptography` | 32 | 32 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `payment-cryptography-data` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pca-connector-ad` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pca-connector-scep` | 12 | 12 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pcs` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `personalize` | 71 | 71 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `personalize-events` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `personalize-runtime` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pi` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pinpoint` | 122 | 122 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pinpoint-email` | 42 | 42 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pinpoint-sms-voice` | 8 | 8 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pinpoint-sms-voice-v2` | 109 | 109 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pipes` | 10 | 0 | 10 | 0 | 0 | 0 | 0 | `-` | 0 |
| `polly` | 10 | 10 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pricing` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `pricing-plan-manager` | 9 | 9 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `proton` | 87 | 87 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `qapps` | 35 | 35 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `qbusiness` | 83 | 83 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `qconnect` | 94 | 94 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `quicksight` | 277 | 277 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ram` | 35 | 35 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `rbin` | 10 | 10 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `rds` | 164 | 164 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `rds-data` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `redshift` | 145 | 4 | 0 | 141 | 0 | 0 | 0 | `default` | 1 |
| `redshift-data` | 12 | 12 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `redshift-serverless` | 65 | 65 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `rekognition` | 75 | 75 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `repostspace` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `resiliencehub` | 63 | 63 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `resiliencehubv2` | 68 | 68 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `resource-explorer-2` | 32 | 32 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `resource-groups` | 23 | 0 | 0 | 23 | 0 | 0 | 0 | `default` | 1 |
| `resourcegroupstaggingapi` | 9 | 0 | 0 | 9 | 0 | 0 | 0 | `default` | 0 |
| `rolesanywhere` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `route53` | 71 | 0 | 0 | 68 | 3 | 0 | 0 | `default` | 2 |
| `route53-recovery-cluster` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `route53-recovery-control-config` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `route53-recovery-readiness` | 32 | 32 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `route53domains` | 34 | 34 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `route53globalresolver` | 48 | 48 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `route53profiles` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `route53resolver` | 72 | 4 | 0 | 39 | 29 | 0 | 0 | `default` | 0 |
| `rtbfabric` | 36 | 36 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `rum` | 20 | 20 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `s3` | 116 | 5 | 22 | 0 | 89 | 0 | 0 | `default` | 2 |
| `s3control` | 97 | 0 | 0 | 94 | 3 | 0 | 0 | `default` | 0 |
| `s3files` | 21 | 21 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `s3outposts` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `s3tables` | 49 | 49 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `s3vectors` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemaker` | 403 | 403 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemaker-a2i-runtime` | 5 | 5 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemaker-edge` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemaker-featurestore-runtime` | 6 | 6 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemaker-geospatial` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemaker-metrics` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemaker-runtime` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sagemakerjobruntime` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `savingsplans` | 10 | 10 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `scheduler` | 12 | 0 | 0 | 12 | 0 | 0 | 0 | `default` | 2 |
| `schemas` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sdb` | 10 | 10 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `secretsmanager` | 23 | 0 | 0 | 12 | 11 | 0 | 0 | `default` | 4 |
| `security-ir` | 24 | 24 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `securityagent` | 92 | 92 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `securityhub` | 117 | 117 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `securitylake` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `serverlessrepo` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `service-quotas` | 26 | 26 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `servicecatalog` | 90 | 90 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `servicecatalog-appregistry` | 24 | 24 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `servicediscovery` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ses` | 71 | 0 | 0 | 64 | 7 | 0 | 0 | `default` | 1 |
| `sesv2` | 112 | 112 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `shield` | 36 | 36 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `signer` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `signer-data` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `signin` | 11 | 11 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `simpledbv2` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sms-voice` | 8 | 8 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `snow-device-management` | 13 | 13 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `snowball` | 27 | 27 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sns` | 42 | 0 | 6 | 0 | 36 | 0 | 0 | `default` | 4 |
| `socialmessaging` | 33 | 33 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sqs` | 23 | 0 | 0 | 0 | 23 | 0 | 0 | `default` | 3 |
| `ssm` | 152 | 6 | 0 | 146 | 0 | 0 | 0 | `default` | 5 |
| `ssm-contacts` | 39 | 39 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ssm-guiconnect` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ssm-incidents` | 31 | 31 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ssm-quicksetup` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `ssm-sap` | 27 | 27 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sso` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sso-admin` | 79 | 79 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sso-oidc` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `stepfunctions` | 37 | 0 | 1 | 0 | 36 | 0 | 0 | `default` | 2 |
| `storagegateway` | 96 | 96 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sts` | 11 | 0 | 0 | 11 | 0 | 0 | 0 | `default` | 0 |
| `supplychain` | 30 | 30 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `support` | 16 | 0 | 0 | 16 | 0 | 0 | 0 | `default` | 0 |
| `support-app` | 10 | 10 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `supportauthz` | 11 | 11 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `sustainability` | 4 | 4 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `swf` | 39 | 0 | 0 | 39 | 0 | 0 | 0 | `default` | 0 |
| `synthetics` | 22 | 22 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `taxsettings` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `textract` | 25 | 25 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `timestream-influxdb` | 24 | 24 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `timestream-query` | 15 | 15 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `timestream-write` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `tnb` | 33 | 33 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `transcribe` | 43 | 0 | 0 | 39 | 4 | 0 | 0 | `default` | 0 |
| `transfer` | 71 | 71 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `translate` | 19 | 19 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `trustedadvisor` | 12 | 12 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `uxc` | 3 | 3 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `verifiedpermissions` | 34 | 34 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `voice-id` | 29 | 29 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `vpc-lattice` | 73 | 73 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `waf` | 77 | 77 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `waf-regional` | 81 | 81 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `wafv2` | 59 | 59 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `wellarchitected` | 72 | 72 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `wickr` | 44 | 44 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `wisdom` | 41 | 41 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `workdocs` | 44 | 44 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `workmail` | 92 | 92 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `workmailmessageflow` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `workspaces` | 91 | 91 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `workspaces-instances` | 13 | 13 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `workspaces-thin-client` | 16 | 16 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `workspaces-web` | 75 | 75 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |
| `xray` | 38 | 38 | 0 | 0 | 0 | 0 | 0 | `-` | 0 |

## Anexo B — todos os modulos AWS CDK

| Modulo | L1s | Providers | Faltantes | Estado estatico | API | Planejamento |
|---|---:|---:|---:|---|---|---|
| `alexa_ask` | 1 | 0 | 1 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_accessanalyzer` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_acmpca` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_aiops` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_amazonmq` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_amplify` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_amplifyuibuilder` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_apigateway` | 22 | 14 | 8 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_apigatewayv2` | 14 | 8 | 6 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_apigatewayv2_authorizers` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_apigatewayv2_integrations` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_appconfig` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_appflow` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_appintegrations` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_applicationautoscaling` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_applicationinsights` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_applicationsignals` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_appmesh` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_apprunner` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_appstream` | 13 | 0 | 13 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_appsync` | 12 | 0 | 12 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_apptest` | 1 | 0 | 1 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_aps` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_arcregionswitch` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_arczonalshift` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_athena` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_auditmanager` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_autoscaling` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_autoscaling_common` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_autoscaling_hooktargets` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_autoscalingplans` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_b2bi` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_backup` | 9 | 0 | 9 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_backupgateway` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_batch` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_bcmdataexports` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_bedrock` | 17 | 0 | 17 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_bedrockagentcore` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_billingconductor` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_budgets` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cases` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cassandra` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ce` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_certificatemanager` | 2 | 1 | 1 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_chatbot` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cleanrooms` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cleanroomsml` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cloud9` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cloudformation` | 18 | 4 | 14 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_cloudfront` | 20 | 0 | 20 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cloudfront_origins` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_cloudtrail` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cloudwatch` | 7 | 2 | 5 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_cloudwatch_actions` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_codeartifact` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codebuild` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codecommit` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codeconnections` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codedeploy` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codeguruprofiler` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codegurureviewer` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codepipeline` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codepipeline_actions` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_codestar` | 1 | 0 | 1 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_codestarconnections` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_codestarnotifications` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cognito` | 16 | 16 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_cognito_identitypool` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_comprehend` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_computeoptimizer` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_config` | 10 | 0 | 10 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_connect` | 34 | 0 | 34 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_connectcampaigns` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_connectcampaignsv2` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_controltower` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_cur` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_customerprofiles` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_databrew` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_datapipeline` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_datasync` | 13 | 0 | 13 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_datazone` | 17 | 0 | 17 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_dax` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_deadline` | 11 | 0 | 11 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_detective` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_devicefarm` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_devopsagent` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_devopsguru` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_directconnect` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_directoryservice` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_dlm` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_dms` | 11 | 0 | 11 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_docdb` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_docdbelastic` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_dsql` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_dynamodb` | 2 | 2 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_ec2` | 111 | 17 | 94 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_ecr` | 9 | 1 | 8 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_ecr_assets` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_ecs` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ecs_patterns` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_efs` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_eks` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_eks_v2` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_elasticache` | 10 | 0 | 10 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_elasticbeanstalk` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_elasticloadbalancing` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_elasticloadbalancingv2` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_elasticloadbalancingv2_actions` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_elasticloadbalancingv2_targets` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_elasticsearch` | 1 | 1 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_emr` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_emrcontainers` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_emrserverless` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_entityresolution` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_events` | 7 | 5 | 2 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_events_targets` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_eventschemas` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_evidently` | 5 | 0 | 5 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_evs` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_finspace` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_fis` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_fms` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_forecast` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_frauddetector` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_fsx` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_gamelift` | 11 | 0 | 11 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_gameliftstreams` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_globalaccelerator` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_globalaccelerator_endpoints` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_glue` | 24 | 0 | 24 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_grafana` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_greengrass` | 16 | 0 | 16 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_greengrassv2` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_groundstation` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_guardduty` | 10 | 0 | 10 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_healthimaging` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_healthlake` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iam` | 16 | 9 | 7 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_identitystore` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_imagebuilder` | 9 | 0 | 9 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_inspector` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_inspectorv2` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_internetmonitor` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_invoicing` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iot` | 30 | 0 | 30 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iotanalytics` | 4 | 0 | 4 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_iotcoredeviceadvisor` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iotevents` | 3 | 0 | 3 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_iotfleethub` | 1 | 0 | 1 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_iotfleetwise` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iotsitewise` | 9 | 0 | 9 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iotthingsgraph` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iottwinmaker` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_iotwireless` | 11 | 0 | 11 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ivs` | 10 | 0 | 10 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ivschat` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_kafkaconnect` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_kendra` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_kendraranking` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_kinesis` | 3 | 2 | 1 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_kinesisanalytics` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_kinesisanalyticsv2` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_kinesisfirehose` | 1 | 1 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_kinesisvideo` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_kms` | 3 | 2 | 1 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_lakeformation` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_lambda` | 11 | 10 | 1 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_lambda_destinations` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_lambda_event_sources` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_lambda_nodejs` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_launchwizard` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_lex` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_licensemanager` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_lightsail` | 15 | 0 | 15 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_location` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_logs` | 15 | 3 | 12 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_logs_destinations` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_lookoutequipment` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_lookoutmetrics` | 2 | 0 | 2 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_lookoutvision` | 1 | 0 | 1 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_m2` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_macie` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_managedblockchain` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mediaconnect` | 12 | 0 | 12 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mediaconvert` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_medialive` | 14 | 0 | 14 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mediapackage` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mediapackagev2` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mediastore` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mediatailor` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_memorydb` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mpa` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_msk` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mwaa` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_mwaaserverless` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_neptune` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_neptunegraph` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_networkfirewall` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_networkmanager` | 16 | 0 | 16 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_nimblestudio` | 4 | 0 | 4 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_notifications` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_notificationscontacts` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_oam` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_observabilityadmin` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_odb` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_omics` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_opensearchserverless` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_opensearchservice` | 2 | 1 | 1 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_opsworks` | 7 | 0 | 7 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_opsworkscm` | 1 | 0 | 1 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_organizations` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_osis` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_panorama` | 3 | 0 | 3 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_paymentcryptography` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_pcaconnectorad` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_pcaconnectorscep` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_pcs` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_personalize` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_pinpoint` | 19 | 0 | 19 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_pinpointemail` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_pipes` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_proton` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_qbusiness` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_qldb` | 2 | 0 | 2 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_quicksight` | 12 | 0 | 12 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ram` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_rbin` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_rds` | 16 | 0 | 16 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_redshift` | 10 | 1 | 9 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_redshiftserverless` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_refactorspaces` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_rekognition` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_resiliencehub` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_resourceexplorer2` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_resourcegroups` | 2 | 1 | 1 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_robomaker` | 6 | 0 | 6 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_rolesanywhere` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_route53` | 7 | 2 | 5 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_route53_patterns` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_route53_targets` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_route53profiles` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_route53recoverycontrol` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_route53recoveryreadiness` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_route53resolver` | 11 | 0 | 11 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_rtbfabric` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_rum` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_s3` | 10 | 2 | 8 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_s3_assets` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_s3_deployment` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_s3_notifications` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_s3express` | 3 | 0 | 3 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_s3objectlambda` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_s3outposts` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_s3tables` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_s3vectors` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_sagemaker` | 34 | 0 | 34 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_sam` | 7 | 0 | 7 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_scheduler` | 2 | 2 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_scheduler_targets` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_sdb` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_secretsmanager` | 4 | 4 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_securityhub` | 15 | 0 | 15 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_securitylake` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_servicecatalog` | 16 | 0 | 16 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_servicecatalogappregistry` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_servicediscovery` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ses` | 21 | 1 | 20 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_ses_actions` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_shield` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_signer` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_simspaceweaver` | 1 | 0 | 1 | `none` | `unmapped` | `no-resource-provider-records` |
| `aws_smsvoice` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_sns` | 4 | 4 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_sns_subscriptions` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_sqs` | 3 | 3 | 0 | `complete` | `mapped` | `all-resource-provider-records-present` |
| `aws_ssm` | 9 | 5 | 4 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_ssmcontacts` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ssmguiconnect` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ssmincidents` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_ssmquicksetup` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_sso` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_stepfunctions` | 4 | 2 | 2 | `partial` | `mapped` | `partial-resource-provider-records` |
| `aws_stepfunctions_tasks` | 0 | 0 | 0 | `not-applicable` | `not-applicable` | `no-l1-resource-types` |
| `aws_supportapp` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_synthetics` | 2 | 0 | 2 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_systemsmanagersap` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_timestream` | 5 | 0 | 5 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_transfer` | 8 | 0 | 8 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_verifiedpermissions` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_voiceid` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_vpclattice` | 14 | 0 | 14 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_waf` | 7 | 0 | 7 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_wafregional` | 11 | 0 | 11 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_wafv2` | 6 | 0 | 6 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_wisdom` | 12 | 0 | 12 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_workspaces` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_workspacesinstances` | 3 | 0 | 3 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_workspacesthinclient` | 1 | 0 | 1 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_workspacesweb` | 10 | 0 | 10 | `none` | `mapped` | `no-resource-provider-records` |
| `aws_xray` | 4 | 0 | 4 | `none` | `mapped` | `no-resource-provider-records` |

## Limites de interpretacao

- A analise e conservadora e estatica. Um provider pode funcionar em cenarios nao promovidos, mas isso nao autoriza uma alegacao de suporte.
- Presenca de handler/provider nao comprova validacao de parametros, erros, paginacao, concorrencia, persistencia, IAM, regioes, quotas ou fidelidade de eventos.
- Fallback nao e equivalente a implementacao enterprise: ownership de estado e atualizacoes de dependencias podem alterar comportamento.
- Cobertura CDK L1 nao mede L2/L3, assets, Docker, lookups, custom resources, transforms ou integracoes cross-service.
- Os cenarios CDK promovidos sao estreitos; nao devem ser extrapolados para suporte global a `cdk bootstrap`, `synth`, `deploy` ou linguagens.
- Este relatorio nao concede acesso a codigo privado ausente, nao contorna licencas e nao transforma uma imagem `community` em feature-complete.
