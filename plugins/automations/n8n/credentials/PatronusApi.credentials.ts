import type { IAuthenticateGeneric, ICredentialTestRequest, ICredentialType, Icon, INodeProperties } from 'n8n-workflow';

export class PatronusApi implements ICredentialType {
  name = 'patronusApi';
  displayName = 'Patronus API';
  icon: Icon = { light: 'file:patronus.svg', dark: 'file:patronus.dark.svg' };
  documentationUrl = 'https://github.com/patronus-protect/patronus-security-cli/tree/main/plugins/automations/n8n#set-up';
  properties: INodeProperties[] = [{
    displayName: 'API Key', name: 'apiKey', type: 'string', default: '', required: true,
    typeOptions: { password: true },
    description: 'Account API key with scan:write and scan:read scopes',
  }];
  authenticate: IAuthenticateGeneric = {
    type: 'generic', properties: { headers: { Authorization: '=Bearer {{$credentials.apiKey}}' } },
  };
  // n8n treats any non-2xx answer as a failed test, so the check is a minimal L1 text scan.
  test: ICredentialTestRequest = {
    request: {
      baseURL: 'https://control.patronus.studio/api/v1', url: '/scan', method: 'POST',
      body: { text: 'Patronus n8n credential check', config: { categories: ['injection'], max_level: 'L1' } },
    },
  };
}
