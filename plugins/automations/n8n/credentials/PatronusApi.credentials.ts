import type { IAuthenticateGeneric, ICredentialType, INodeProperties } from 'n8n-workflow';

export class PatronusApi implements ICredentialType {
  name = 'patronusApi';
  displayName = 'Patronus API';
  icon = 'file:patronus.png' as const;
  documentationUrl = 'https://docs.patronus.studio';
  properties: INodeProperties[] = [{
    displayName: 'API Key', name: 'apiKey', type: 'string', default: '', required: true,
    typeOptions: { password: true },
    description: 'Account API key with scan:write and scan:read scopes',
  }];
  authenticate: IAuthenticateGeneric = {
    type: 'generic', properties: { headers: { Authorization: '=Bearer {{$credentials.apiKey}}' } },
  };
}
