// this should match the Rust Operation enum structure
export type ServiceChallenge = {
	Signed: object;
  };
  
  export type ServiceChallengeInput = {
	Signed: object;
  };
  
  export type HashchainSignatureBundle = {
	key_idx: number;
	signature: object;
  };
  
  export type CreateAccountArgs = {
	id: string;
	value: object; 
	signature: object;
	service_id: string;
	challenge: ServiceChallengeInput;
  };
  
  export type RegisterServiceArgs = {
	id: string;
	creation_gate: ServiceChallenge;
  };
  
  export type KeyOperationArgs = {
	id: string;
	value: object;
	signature: HashchainSignatureBundle;
  };
  
  export type AddDataArgs = {
	id: string;
	value: object;
	value_signature: {
	  verifying_key: string;
	  signature: object;
	} | null;
	op_signature: HashchainSignatureBundle;
  };
  
  export type Operation = 
	| { CreateAccount: CreateAccountArgs }
	| { RegisterService: RegisterServiceArgs }
	| { AddKey: KeyOperationArgs }
	| { RevokeKey: KeyOperationArgs }
	| { AddData: AddDataArgs };