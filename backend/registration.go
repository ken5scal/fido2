package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
	"unicode/utf8"
	"fmt"
)

// ServerPublicKeyCredentialCreationOptionsRequest
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsrequest
type ServerPublicKeyCredentialCreationOptionsRequest struct {
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`

	// https://w3c.github.io/webauthn/#authenticatorSelection
	AuthenticatorSelectionCriteria struct {
		RequireResidentKey bool `json:"residentKey"` // default = false
		//https://w3c.github.io/webauthn/#attachment
		//It is Enum with either value {"platform","cross-platform"}
		AuthenticationAttachment string `json:"authenticatorAttachment,omitempty"` // no default
		//https://w3c.github.io/webauthn/#userVerificationRequirement
		//It is Enum with either value {"required","preferred","discouraged"}
		UserVerificationRequirement string `json:"userVerification"` // default = preferred
	} `json:"authenticatorSelection,omitempty"`

	//https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference
	//It is Enum with either value {"none","indirect","direct"}
	AttestationConveyancePreference AttestationConveyancePreference `json:"attestation,omitempty"` // default="none"
}

func (s ServerPublicKeyCredentialCreationOptionsRequest) validate() error {
	if s.UserName != "" && s.DisplayName != "" {
		return nil
	}
	return errors.New("Both userName and displayName must be present")
}

type AuthenticatorAttachment int

const (
	_ AuthenticatorAttachment = iota
	Platform
	CrossPlatform
)

func (a AuthenticatorAttachment) String() string {
	return toStringAA[a]
}

var toStringAA = map[AuthenticatorAttachment]string{
	Platform:      "platform",
	CrossPlatform: "cross-platform",
}

func (a *AuthenticatorAttachment) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(a.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (a *AuthenticatorAttachment) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	switch j {
	case "platform":
		*a = Platform
	case "cross-platform":
		*a = CrossPlatform
	default:
		return errors.New("Invalid Authenticator Attachment. Must be either 'platform' or 'cross-platform'")
	}
	return nil
}

type UserVerificationRequirement int

const (
	_ UserVerificationRequirement = iota
	Required
	Preferred
	Discouraged
)

func (u UserVerificationRequirement) String() string {
	return toStringUV[u]
}

var toStringUV = map[UserVerificationRequirement]string{
	Required:    "required",
	Preferred:   "preferred",
	Discouraged: "discouraged",
}

func (u *UserVerificationRequirement) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(toStringUV[*u])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (u *UserVerificationRequirement) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	switch j {
	case "required":
		*u = Required
	case "discouraged":
		*u = Discouraged
	case "preferred":
		*u = Preferred
	default:
		*u = Preferred //Preferred is the default value
	}
	return nil
}

type AttestationConveyancePreference int

const (
	_ AttestationConveyancePreference = iota
	None
	Indirect
	Direct
)

func (a AttestationConveyancePreference) String() string {
	return toString[a]
}

var toString = map[AttestationConveyancePreference]string{
	None:     "none",
	Indirect: "indirect",
	Direct:   "direct",
}

func (a *AttestationConveyancePreference) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(toString[*a])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (a *AttestationConveyancePreference) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	switch j {
	case "indirect":
		*a = Indirect
	case "direct":
		*a = Direct
	case "none":
		*a = None
	default:
		*a = None // None is default value
	}
	return nil
}

// ServerPublicKeyCredentialCreationOptionsResponse
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredentialcreationoptionsresponse
type ServerPublicKeyCredentialCreationOptionsResponse struct {
	// Required
	Challenge                   string `json:"challenge"`
	PublicKeyCredentialRpEntity struct {
		Name string `json:"name"`
	} `json:"rp"`
	ServerPublicKeyCredentialUserEntity struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PublicKeyCredentialParameters []PubKeyParam `json:"pubKeyCredParams"`

	// Optional
	Timeout                        uint64              `json:"timeout,omitempty"`
	ExcludeCredentials             []ExcludeCredential `json:"excludeCredentials,omitempty"`
	AuthenticatorSelectionCriteria struct {
		ResidentKey             bool   `json:"residentKey"`
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		UserVerification        string `json:"userVerification"`
	} `json:"authenticatorSelection,omitempty"`
	Attestation string `json:"attestation,omitempty"` // default="none"
	// AuthenticationExtensionsClientInputs  struct{} //TODO 一旦無視
}

type PubKeyParam struct {
	Type string `json:"type"` //今は固定 publick-key: https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
	Alg  int    `json:"alg"`  //https://w3c.github.io/webauthn/#alg-identifier
}

type ExcludeCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ServerPublicKeyCredential
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
type ServerPublicKeyCredential struct {
	// This attribute is inherited from Credential, though ServerPublicKeyCredential overrides it with base64url encoding of the authenticator credId
	ID string `json:"id"`
	// same as id
	RawID string `json:"rawId"`
	// a dictionary defined as ServerAuthenticatorAttestationResponse or by ServerAuthenticatorAttestationResponse
	AuthenticatorAttestationResponse ServerAuthenticatorAttestationResponse `json:"response"`
	// This attribute is inherited from Credential, though ServerPublicKeyCredential overrides it with "public-key"
	Type string `json:"type"` // public-key固定
	// ???  map containing extension identifier, which contain client extension output entries produced by the extension’s client extension processing
	AuthenticationExtensionsClientOutputs struct{} `json:"getClientExtensionResults"`
}

type ServerAuthenticatorAttestationResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`    //base64url encoded clientDataJSON buffer
	AttestationObject string `json:"attestationObject"` //base64url encoded attestationObject buffer
}

// ClientDataJSON
// https://www.w3.org/TR/webauthn/#sec-client-data
type ClientData struct {
	Type        string       `json:"type"`
	Challenge   string       `json:"challenge"`
	Origin      string       `json:"origin"`
	TokenBiding TokenBinding `json:"tokenBinding"`
}

// TokenBinding
// https://www.w3.org/TR/webauthn/#sec-client-data
type TokenBinding struct {
	TokenBindingStatus TokenBindingStatus `json:"status"`
	ID                 string             `json:"id"`
}

type TokenBindingStatus int

const (
	_ TokenBindingStatus = iota
	Present
	Supported
	NotSupported //?Not really shown in https://www.w3.org/TR/webauthn/#sec-client-data
)

// Validate
// WebAuthN: 7.1
// https://www.w3.org/TR/webauthn/#registering-a-new-credential
var hashOfClientData string

// ClientDataJSON: eyJjaGFsbGVuZ2UiOiJEa1hCdWRCa2wzTzBlTUV5SGZBTVgxT2tRbHV4c2hjaW9WU3dITVJMUlhtd044SXJldHg3cWJ0MWx3Y0p4d0FxWUU0SUxTZjVwd3lHMEhXSWtEekVMUT09Iiwib3JpZ2luIjoid2ViYXV0aG4ub3JnIiwiaGFzaEFsZyI6IlNIQS0yNTYifQ
// AttestationObject:
// 下記にある例はAndroid SafetyNetAttestationの証明書の有効期限がきれている。
// https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#validating-attestation
// よって、こちらの例にあったものを使うべし -> https://medium.com/@herrjemand/verifying-fido2-safetynet-attestation-bd261ce1978d
//  {
//      "fmt": "android-safetynet",
//      "authData": "9569088f1ecee3232954035dbd10d7cae391305a2751b559bb8fd7cbb229bdd4450000000000000000000000000000000000000000004101552f0265f6e35bcc29877b64176690d59a61c3588684990898c544699139be88e32810515987ea4f4833071b646780438bf858c36984e46e7708dee61eedcbd0a5010203262001215820db750914e19e62e1d210ce9504afd851930f48f91f714870387aa519fb371d0f22582091fcc0cb23c24345447e36b5be4d174c517394531d0ce788382d32f232571ae0",
//      "attStmt": {
//      "ver": "14366019",
//      "response": "65794a68624763694f694a53557a49314e694973496e67315979493657794a4e53556c476132704451304a496357644264306c435157644a55564a59636d394f4d4670505a464a72516b46425155464251564231626e7042546b4a6e6133466f61326c484f586377516b465263305a4252454a445456467a64304e5257555257555646485258644b566c56365257564e516e64485154465652554e6f54565a534d6a6c32576a4a3462456c47556e6c6b5745347753555a4f62474e75576e425a4d6c5a3654564a4e6430565257555257555646455258647753465a47545764524d45566e54565534654531434e46684556455530545652426545314551544e4e56477377546c5a76574552555254564e56454633543152424d303155617a424f566d3933596b524654453142613064424d565646516d684e51315a5754586846656b4653516d644f566b4a425a3152446130356f596b64736257497a536e566856305634526d704256554a6e546c5a4351574e5552465578646d52584e54425a5632783153555a616346705959336846656b4653516d644f566b4a426231524461325232596a4a6b63317054516b31555255313452337042576b4a6e546c5a4351553155525731474d475248566e706b517a566f596d3153655749796247744d62553532596c5244513046545358644555566c4b53323961535768325930354255555643516c46425247646e5256424252454e44515646765132646e52554a42546d705961336f775a5573785530553062537376527a5633543238725745645452554e79635752754f44687a513342534e325a7a4d54526d537a425361444e6151316c6154455a4963554a724e6b4674576c5a334d6b7335526b6377547a6c79556c426c5555524a566c4a3552544d7755585675557a6c315a3068444e47566e4f573932646b39744b31466b576a4a774f544e5961487031626c46466146565857454e345155524a5255644b537a4e544d6d46425a6e706c4f546c5154464d794f57684d5931463157566849524746444e3039616355357562334e70543064705a6e4d34646a467161545a494c33686f62485244576d557962456f724e3064316448706c6545747765485a7752533930576c4e6d596c6b354d4456785532784361446c6d63476f774d54566a616d3552526d7456633046566432314c566b465664575656656a523053324e47537a52775a585a4f54474634525546734b3039726157784e64456c5a5247466a524456755a5777306545707065584d304d544e6f59576478567a425861476731526c417a4f576848617a6c464c304a3355565271595870546545646b646c677762545a34526c6c6f61433879566b3135576d70554e457436554570465130463352554642595539445157786e6432646e536c564e51545248515446565a45523352554976643146465158644a526d3945515652435a30355753464e5652555245515574435a326479516d6446526b4a52593052425645464e516d644f566b685354554a425a6a684651577042515531434d4564424d56566b5247645256304a4355584643555864485632394b516d45786231524c63585677627a52584e6e68554e6d6f795245466d516d644f566b685454555648524546585a304a545754426d6148564654335a51625374345a323534615646484e6b52795a6c46754f557436516d74435a326479516d6446526b4a5259304a4255564a5a54555a5a6430703357556c4c64316c43516c465653453142523064484d6d67775a4568424e6b78354f585a5a4d30353354473543636d46544e5735694d6a6c7554444a6b4d474e36526e5a4e56454679516d646e636b4a6e52555a4355574e335157395a5a6d4649556a426a5247393254444e43636d46544e5735694d6a6c7554444a6b656d4e7153585a534d564a555456553465457874546e6c6b5245466b516d644f566b685352555647616b46565a32684b61475249556d786a4d3146315756633161324e744f584261517a5671596a497764306c5257555257556a426e516b4a766430644551556c435a3170755a314633516b466e5358644551566c4c5333645a516b4a425346646c55556c4751587042646b4a6e546c5a49556a684653305242625531445532644a6355466e6147673162325249556e64506154683257544e4b63307875516e4a68557a5675596a4935626b77775a465656656b5a5154564d31616d4e746433646e5a305646516d6476636b4a6e525556425a466f315157645251304a4a53444643535568355156424251575233513274315557315264454a6f57555a4a5a5464464e6b784e576a4e425331424556316c43554774694d7a6471616d51344d45393551544e6a5255464251554658576d52454d31424d5155464252554633516b6c4e52566c4453564644553170445632564d536e5a7a61565a584e6b4e6e4b3264714c7a6c335756524b556e70314e456870635755305a566b3059793974655870715a306c6f51557854596d6b76564768365933707864476c714d3252724d335a6954474e4a567a4e4d62444a434d4738334e5564525a47684e61576469516d644253465642566d6852523231704c316833645870554f5756484f564a4d535374344d466f7964574a35576b5657656b45334e564e5a566d5268536a424f4d45464251555a7457464535656a56425155464351553142556d704352554670516d4e4464304535616a644f56456459554449334f486f306148497664554e496155464754486c7651334579537a41726555785364307056596d644a5a3259345a306871646e42334d6d31434d555654616e45795432597a5154424252554633513274755132464653305a5665566f335a69395264456c335246465a536b7476576b6c6f646d4e4f5156464654454a525155526e5a30564351556b35626c526d556b744a56326430624664734d33644354445531525652574e6d7468656e4e77614663786555466a4e55523162545a59547a51786131703664306f324d58644b62575253556c517656584e4453586b78533056304d6d4d775257706e6247354b513059795a574633593056586245785257544a5955457835526d70725631464f596c4e6f516a46704e466379546c4a48656c426f64444e744d5749304f57686963335231574530326446673151336c465347355561446843623230304c316473526d6c6f656d686e626a67785247786b623264364c3073795658644e4e6c4d32513049765530563461326c575a6e5972656d4a4b4d484a71646d63354e4546735a4770565a6c563361306b35566b354e616b56514e575534655752434d32394d62445a6e624842445a5559315a47646d5531673056546c344d7a56766169394a5357517a565555765a464277596939785a3064326332746d5a475636644731566447557653314e74636d6c33593264565631646c57475a55596b6b7a656e4e7061336461596d747762564a5a533231715547316f646a527962476c3652304e4864446851626a68776354684e4d6b74455a6939514d3274576233517a5a544534555430694c434a4e53556c4655327044513046365332644264306c435157644a546b466c547a42746355644f61584674516b7058624646315245464f516d64726357687261556335647a42435156467a526b4645516b314e553046335347645a52465a525555784665475249596b633561566c58654652685632523153555a4b646d497a555764524d45566e54464e43553031715256524e516b56485154465652554e6f545574534d6e6832575731476331557962473569616b565554554a4652304578565556426545314c556a4a34646c6c74526e4e564d6d7875596d70425a555a334d48684f656b457954565256643031455158644f52457068526e63776555315552586c4e564656335455524264303545536d464e52556c3451337042536b4a6e546c5a4351566c5551577857564531534e48644951566c45566c465253305634566b68694d6a6c75596b64565a315a49536a466a4d31466e56544a5765575274624770615745313452587042556b4a6e546c5a43515531555132746b56565635516b525255304634564870466432646e52576c4e5154424851314e7852314e4a596a4e4555555643515646565155453053554a45643046335a3264465330467653554a425555525252303035526a464a646b34774e587072555538354b33524f4d58424a556e5a4b656e703554315249567a5645656b5661614551795a564244626e5a5651544252617a4934526d644a51325a4c63554d355257747a517a52554d6d5a58516c6c724c3270445a6b4d7a556a4e57576b316b5579396b546a526153304e4655467053636b463652484e7053315645656c4a7962554a43536a56336457526e656d356b5355315a5930786c4c314a4852305a734e586c5052456c4c5a32704664693954536b6776565577725a4556686248524f4d54464362584e4c4b325652625531474b79744259336848546d68794e546c7854533835615777334d556b795a453434526b646d5932526b643356685a576f30596c686f6344424d59314643596d703454574e4a4e3070514d47464e4d31513053537445633246346255744763324a71656d4655546b4d3564587077526d786e54306c6e4e334a534d6a563462336c75565868324f485a4f625774784e33706b554564495747743456316b33623063356169744b61314a35516b4643617a6459636b706d6233566a516c704663555a4b536c4e51617a64595154424d5331637757544e364e5739364d6b5177597a4630536b74335345466e54554a42515564715a326446656b314a53554a4d656b4650516d644f566b68524f454a425a6a6846516b464e5130465a5758644955566c45566c497762454a435758644751566c4a5333645a516b4a52565568426430564851304e7a5230465256555a436430314454554a4a5230457856575246643056434c3364525355314257554a425a6a6844515646426430685257555257556a4250516b4a5a52555a4b616c4972527a52524e6a6772596a644851325a48536b4669623039304f554e6d4d484a4e516a6848515446565a456c3355566c4e516d4642526b7032615549785a473549516a6442595764695a5664695532464d5a43396a52316c5a645531455655644451334e4851564656526b4a3352554a4351327433536e704262454a6e5a334a435a305647516c466a6430465a575670685346497759305276646b77794f57706a4d30463159306430634578745a485a694d6d4e32576a4e4f6555317151586c435a30355753464934525574365158424e5132566e536d4642616d6870526d396b53464a3354326b34646c6b7a536e4e4d626b4a7959564d31626d49794f57354d4d6d52365932704a646c6f7a546e6c4e61545671593231336431423357555257556a426e516b526e64303571515442435a3170755a314633516b466e5358644c616b4676516d646e636b4a6e52555a4355574e4451564a5a59324649556a426a5345303254486b3564324579613356614d6a6c32576e6b3565567059516e5a6a4d6d7777596a4e4b4e557836515535435a32747861477470527a6c334d454a4255584e4751554650513046525255464862304572546d35754e7a68354e6e4253616d513557477852563035684e3068555a326c614c33497a556b35486132315662566c49554646784e6c4e6a64476b3555455668616e5a33556c517961566455534646794d444a6d5a584e785433464357544a46564656335a3170524b3278736447394f526e5a6f6330383564485a435130394a5958707763336458517a6c68536a6c34616e55306446644555556734546c5a564e6c6c615769395964475645553064564f566c36536e4651616c6b3463544e4e52486879656d31785a58424351325931627a687464793933536a52684d6b633265487056636a5a47596a5a554f45316a524538794d6c424d556b773264544e4e4e465236637a4e424d6b3078616a5a696557744b57576b346431644a556d5242646b744d563170314c324634516c5a69656c6c746357313361323031656b785452466331626b6c42536d4a4654454e5251317033545567314e6e517952485a7862325a34637a5a43516d4e44526b6c6156564e776548553265445a305a4442574e314e32536b4e4462334e70636c4e7453574630616938355a464e54566b525261574a6c644468784c7a6456537a52324e467056546a677759585275576e6f786557633950534a6466512e65794a756232356a5a534936496c6851516a64575647525357474a454d30316d4d454e76544646355a564a51636c41355a6a497a5957396d5648427456576436636d6c72627a41394969776964476c745a584e305957317754584d694f6a45314e4441324e5445324f4451774f544d73496d467761314268593274685a32564f5957316c496a6f69593239744c6d6476623264735a533568626d527962326c6b4c6d647463794973496d4677613052705a32567a64464e6f595449314e694936496d565259797432656c566a5a486777526c5a4f54485a5953485648634551774b3149344d44647a565556326343744b5a57786c5756707a61554539496977695933527a55484a765a6d6c735a55316864474e6f496a7030636e566c4c434a68634774445a584a3061575a70593246305a5552705a32567a64464e6f595449314e694936577949345544467a567a42465545706a633278334e315636556e4e70574577324e486372547a557752575172556b4a4a513352686554466e4d6a524e50534a644c434a6959584e7059306c756447566e636d6c306553493664484a315a58302e656d596179456d635a52356e477951307961795a49775361387a4443347a4357647a7668397365523368585942636d56396c4c36506d57702d483538464d6e75456168483248674d4179486f3078506a4230787231517a467a73624e6d4573432d5f4c6f746176694d33564975576168656a6b785f526f622d3071337668437143597972614d695463466b7a4e2d6258676175424f304d6439654147464252355030704c6e7569385f3668706f3677524e4137346c474b4173306b4f693441396a5573374e612d41344f6165795973385133713432355337667536507a61646b34726b5a636c66457650496a4d71464643434f2d5f6c6c587648546170345330395f5736744670525f6377394a584c37673564556363613569576f445a78587a74734b527a3370316341314d32676b5a736d4d57435944364b7634424973487469697477684c32534e4338515a6959633157786a3341"
//  }
//let safetyNetWebAuthnSample = {
//"rawId": "AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c",
//"id": "AZD7huwZVx7aW1efRa6Uq3JTQNorj3qA9yrLINXEcgvCQYtWiSQa1eOIVrXfCmip6MzP8KaITOvRLjy3TUHO7_c",
//"response": {
//"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVGY2NWJTNkQ1dGVtaDJCd3ZwdHFnQlBiMjVpWkRSeGp3QzVhbnM5MUlJSkRyY3JPcG5XVEs0TFZnRmplVVY0R0RNZTQ0dzhTSTVOc1pzc0lYVFV2RGciLCJvcmlnaW4iOiJodHRwczpcL1wvd2ViYXV0aG4ub3JnIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0",
//"attestationObject": "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE0MzY2MDE5aHJlc3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVVkpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXbkJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROTlZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4MVNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSVzFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQlJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPRGh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKNVJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTek5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSbXRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3MGVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQzh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkSlJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRVTFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoVFRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZMEpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1aU1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGMVdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRMEpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RNE1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LMmRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaaVRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNRm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFNWFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNbTFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiVFpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4UldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTRzVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWVGw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daVVlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTVVpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKRlIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlVTFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWNFZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQlVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRVEJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0UmtkbVkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKNVFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UVUpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaamhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoSFFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRVkZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkMGNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkbGt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1cVFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGSGIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVRVZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5SllYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SSGh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSNmN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tORGIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmUS5leUp1YjI1alpTSTZJa2tyVW5GVE1IVnZlSEpKYld0MkwxTXJOa3hZVlhwMlNrVTJRVkZ5UkRGNGJEQjVTM2Q0TW0xS1NUUTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOREV6TXpZM01qazVNekFzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJbVZSWXl0MmVsVmpaSGd3UmxaT1RIWllTSFZIY0VRd0sxSTRNRGR6VlVWMmNDdEtaV3hsV1ZwemFVRTlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5XTGV3N1FqemM2QTZHeVZfck1VRlhSZzEyVEtSb0ROLXJhSG9NSzY3SGdCbk5Yc0QtOUtjaG1TVFpBWWZfLXFKZE1wN1BhYml4VnF4ZDdDQzFxTFBPaUZYLVd5RGJzZlltNmRabFFiODhSd2R6LVEyUVJfTDFCN3NTaURlV1lTeDZmMm10MlQ0WXQ4MjNGNHNGYk8zVlpXM1RacmRRLXBlMVFWMEZYTTRUQ1dXbWVVRUUyWEJmaFVYbHJ5MEFicWhnQUNsWWFGcG8xdUhXUjhEOFkweDhtUDFocmVTMUtNN2NfT01lc1E5dl9mdlBETUE0SEUtYlpZbHZrRVV2VmFCeFpWVzB2SXN4eWxiWllSNVMxSjIwSXRPLV9kSDFERWRkY1kzcmc3bzd6RlJGSGFnd0QyN3dCMzlCTmk4cVNVcG1heEk1VWhrNE04X3BDSWtmLXBwaUFoYXV0aERhdGFYxZVpCI8ezuMjKVQDXb0Q18rjkTBaJ1G1WbuP18uyKb3URQAAAAAAAAAAAAAAAAAAAAAAAAAAAEEBkPuG7BlXHtpbV59FrpSrclNA2iuPeoD3Kssg1cRyC8JBi1aJJBrV44hWtd8KaKnozM_wpohM69EuPLdNQc7v96UBAgMmIAEhWCBVEWSlJerLbRupcvBaXA5Cqpp1Ba46HZTH-dqgmeMCYSJYIIlzYLPXaVavxbpZ4G6ZJWJ6hwW_NgiKAHpSNL8Bwf_d"
//}
//}
func (s ServerAuthenticatorAttestationResponse) Validate(challenge, origin string) error {
	clientDataInBytes, err := base64.RawURLEncoding.DecodeString(s.ClientDataJSON)
	if err != nil {
		return errors.New("Failed Decoding ClientDataJSON")
	}

	// 7.1.1
	// https://www.w3.org/TR/webauthn/#registering-a-new-credential
	if utf8.Valid(clientDataInBytes) {
		return errors.New("Invalid json")
	}

	// 7.1.2
	var clientData ClientData
	if err := json.Unmarshal(clientDataInBytes, &clientData); err != nil {
		return errors.New("Failed Unmarshal ClientDataJSON")
	}

	// 7.1.3
	// TODO make this enum
	if clientData.Type != "webauthn.create" {
		return errors.New("ClientData type is not 'webauthn.create'")
	}

	// 7.1.4
	if clientData.Challenge != challenge {
		return errors.New("ClientData challenge is not same as the one from ServerPublicKeyCredentialCreationOptionsResponse")
	}

	// 7.1.5
	// given a Relying Party whose origin is https://login.example.com:1337, then the following RP IDs are valid: login.example.com (default) and example.com, but not m.login.example.com and not com
	// https://www.w3.org/TR/webauthn/#webauthn-relying-party
	// TODO Implement Correctly
	if clientData.Origin != origin {
		return errors.New("ClientData challenge is not same as the origin")
	}

	// 7.1.6
	// TODO Skip for now (Got No Idea)
	//if clientData.TokenBiding.TokenBindingStatus == {
	//
	//}

	// 7.1.7
	sha := sha256.New()
	sha.Write(clientDataInBytes)
	hashOfClientData := hex.EncodeToString(sha.Sum(nil))
	fmt.Println(hashOfClientData)

	// 7.1.8 CBOR Decoding
	cborByte := make([]byte, base64.RawURLEncoding.DecodedLen(len(s.AttestationObject)))
	cborByte, err = base64.RawURLEncoding.DecodeString(s.AttestationObject)
	if err != nil {
		return errors.Wrap(err, "failed base64 url decoding AttestationObject")
	}

	// TODO Not quite sure how to extract AttObj based on not yet decoded Format
	ao := AttestationObject{}
	//var ao interface{}
	if err := codec.NewDecoderBytes(cborByte, new(codec.CborHandle)).Decode(&ao); err != nil {
		return errors.Wrap(err, "failed cbor decoding AttestationObject")
	}

	// 7.1.9 Verifying that the RP ID hash in auth Data is sha256 of RP ID
	// AuthData: https://www.w3.org/TR/webauthn/#authenticator-data
	if len(ao.AuthData) < 37 {
		return errors.New("AuthData must be 37 bytes or more")
	}
	sha.Write([]byte(rp))
	rpIdHash := hex.EncodeToString(sha.Sum(nil))
	if rpIdHash != hex.EncodeToString(ao.AuthData[0:32]) {
		return errors.New("RP ID Hash in authData is not SHA-256 hash of the RP ID")
	}

	// 7.1.10 Verify UP bit of the flags in authData is set
	// 7.1.11 Verify UV bit of the flags in authData is set IF it is required
	flags := ao.AuthData[32]
	up := flags & (1 << 0) >> 0
	uv := flags & (1 << 2) >> 2
	//attestedClientData := flags & (1 << 6) >> 6
	doesIncludeExtensions := flags & (1 << 7) >> 7

	if up == 0 {
		// https://www.w3.org/TR/webauthn/#test-of-user-presence
		return errors.New("Requires user interaction with an authenticator (Not necessary has to be verification)")
	}

	if requiresUserVerification && uv == 0 {
		return errors.New("Requires user verification by an authenticator.")
	}

	// 7.1.12 Verifying the client extension
	if doesIncludeExtensions == 1 {
		// TODO Study and implement extetion verification
		// https://www.w3.org/TR/webauthn/#sctn-extension-id
	}

	// 7.1.13 Determine the attestation statement
	// 7.1.14 Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.
	// 7.1.15 If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy.
	// 7.1.16 Assess the attestation trustworthiness using the outputs of the verification procedure in step 14
	// TODO 7.1.19 If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.
	switch ao.Fmt {
	case "packed":
	case "tpm":
	case "android-key":
	case "android-safetynet":
	case "fido-u2f":
	case "none":
	}

	// TODO 7.1.17 Check that the credentialId is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony,
	// TODO 7.1.18 If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.
	return nil
}

//============================================
// Attestation Object
//============================================

// Attestation Object
// https://www.w3.org/TR/webauthn/#generating-an-attestation-object
type AttestationObject struct {
	Fmt string `codec:"fmt"`
	//AttStmt []byte  `codec:"attStmt"`
	AttStmt  AttestationStmt `codec:"attStmt"`
	AuthData []byte          `codec:"authData"`
}

// AttestationStatement
// The format varies based on Attestation Format
// https://www.w3.org/TR/webauthn/#sctn-attstn-fmt-ids

type AttestationStmt interface {
	Verify() bool
}

// AndroidKeyAttestation
// https://www.w3.org/TR/webauthn/#android-key-attestation
type AndroidKeyAttestationStmt struct {
	Sig []byte   `codec:"sig"`
	X5c [][]byte `codec:"x5c"`
}

func (a AndroidKeyAttestationStmt) Verify() bool {
	return false
}

// AndroidSafetyNetAttestationStmt
// https://www.w3.org/TR/webauthn/#android-safetynet-attestation
type AndroidSafetyNetAttestationStmt struct {
	Ver      string `codec:"ver"`      // The version number of Google Play Services responsible for providing the SafetyNet API
	Response []byte `codec:"response"` //The UTF-8 encoded result of the getJwsResult() call of the SafetyNet API. This value is a JWS object
}

func (a AndroidSafetyNetAttestationStmt) Verify() bool {
	return false
}
