import React, { useState, useEffect } from 'react';
import {
  handleARDisplay,
  handleThemeCustomization,
  getVoiceCommandSettings,
  updateVoiceCommandSettings,
  listWidgets,
  addWidget,
  removeWidget,
  resolveAlias,
  registerAlias,
  removeAlias,
} from '../api_service/wallet_display_api_service';

const WalletDisplayGui = () => {
  const [walletId, setWalletId] = useState('');
  const [arDisplayData, setArDisplayData] = useState(null);
  const [theme, setTheme] = useState({ name: '', settings: {} });
  const [voiceSettings, setVoiceSettings] = useState({ enabled: false, locale: 'en-US' });
  const [widgets, setWidgets] = useState([]);
  const [alias, setAlias] = useState('');
  const [address, setAddress] = useState('');
  const [resolvedAddress, setResolvedAddress] = useState('');

  useEffect(() => {
    fetchVoiceSettings();
    fetchWidgets();
  }, []);

  const fetchVoiceSettings = async () => {
    try {
      const settings = await getVoiceCommandSettings();
      setVoiceSettings(settings);
    } catch (error) {
      console.error('Error fetching voice command settings:', error);
    }
  };

  const fetchWidgets = async () => {
    try {
      const widgetList = await listWidgets();
      setWidgets(widgetList);
    } catch (error) {
      console.error('Error fetching widgets:', error);
    }
  };

  const handleARDisplayClick = async () => {
    try {
      const data = await handleARDisplay(walletId);
      setArDisplayData(data);
    } catch (error) {
      console.error('Error handling AR display:', error);
    }
  };

  const handleThemeCustomizationClick = async () => {
    try {
      await handleThemeCustomization(theme);
      alert('Theme customized successfully');
    } catch (error) {
      console.error('Error customizing theme:', error);
    }
  };

  const handleVoiceCommandUpdate = async () => {
    try {
      await updateVoiceCommandSettings(voiceSettings);
      alert('Voice command settings updated successfully');
    } catch (error) {
      console.error('Error updating voice command settings:', error);
    }
  };

  const handleAddWidget = async () => {
    const widgetId = prompt('Enter widget ID:');
    const widgetData = {}; // Collect necessary widget data
    try {
      await addWidget(widgetId, widgetData);
      fetchWidgets(); // Refresh widget list
      alert('Widget added successfully');
    } catch (error) {
      console.error('Error adding widget:', error);
    }
  };

  const handleRemoveWidget = async (id) => {
    try {
      await removeWidget(id);
      fetchWidgets(); // Refresh widget list
      alert('Widget removed successfully');
    } catch (error) {
      console.error('Error removing widget:', error);
    }
  };

  const handleResolveAlias = async () => {
    try {
      const resolvedAddr = await resolveAlias(alias);
      setResolvedAddress(resolvedAddr);
    } catch (error) {
      console.error('Error resolving alias:', error);
    }
  };

  const handleRegisterAlias = async () => {
    try {
      await registerAlias(alias, address);
      alert('Alias registered successfully');
    } catch (error) {
      console.error('Error registering alias:', error);
    }
  };

  const handleRemoveAlias = async () => {
    try {
      await removeAlias(alias);
      alert('Alias removed successfully');
    } catch (error) {
      console.error('Error removing alias:', error);
    }
  };

  return (
    <div>
      <h1>Wallet Display Management</h1>
      
      <div>
        <h2>AR Display</h2>
        <input
          type="text"
          placeholder="Wallet ID"
          value={walletId}
          onChange={(e) => setWalletId(e.target.value)}
        />
        <button onClick={handleARDisplayClick}>Handle AR Display</button>
        {arDisplayData && <pre>{JSON.stringify(arDisplayData, null, 2)}</pre>}
      </div>
      
      <div>
        <h2>Theme Customization</h2>
        <input
          type="text"
          placeholder="Theme Name"
          value={theme.name}
          onChange={(e) => setTheme({ ...theme, name: e.target.value })}
        />
        <textarea
          placeholder="Theme Settings"
          value={JSON.stringify(theme.settings, null, 2)}
          onChange={(e) => setTheme({ ...theme, settings: JSON.parse(e.target.value) })}
        />
        <button onClick={handleThemeCustomizationClick}>Customize Theme</button>
      </div>
      
      <div>
        <h2>Voice Command Settings</h2>
        <label>
          Enabled:
          <input
            type="checkbox"
            checked={voiceSettings.enabled}
            onChange={(e) => setVoiceSettings({ ...voiceSettings, enabled: e.target.checked })}
          />
        </label>
        <input
          type="text"
          placeholder="Locale"
          value={voiceSettings.locale}
          onChange={(e) => setVoiceSettings({ ...voiceSettings, locale: e.target.value })}
        />
        <button onClick={handleVoiceCommandUpdate}>Update Voice Command Settings</button>
      </div>
      
      <div>
        <h2>Widgets</h2>
        <button onClick={handleAddWidget}>Add Widget</button>
        <ul>
          {widgets.map((widget) => (
            <li key={widget.id}>
              {widget.name} <button onClick={() => handleRemoveWidget(widget.id)}>Remove</button>
            </li>
          ))}
        </ul>
      </div>
      
      <div>
        <h2>Wallet Naming</h2>
        <input
          type="text"
          placeholder="Alias"
          value={alias}
          onChange={(e) => setAlias(e.target.value)}
        />
        <input
          type="text"
          placeholder="Address"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
        />
        <button onClick={handleRegisterAlias}>Register Alias</button>
        <button onClick={handleResolveAlias}>Resolve Alias</button>
        <button onClick={handleRemoveAlias}>Remove Alias</button>
        {resolvedAddress && <p>Resolved Address: {resolvedAddress}</p>}
      </div>
    </div>
  );
};

export default WalletDisplayGui;
