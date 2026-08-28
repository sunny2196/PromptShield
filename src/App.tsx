import React, { useState } from 'react';
import {
  Plus,
  Folder,
  Code2,
  SlidersHorizontal,
  Layers,
  Palette,
  ChevronDown,
  Search,
  PanelLeft,
  Mic,
  HelpCircle,
  MessageSquare,
} from 'lucide-react';
import PromptShield from './components/PromptShield';

export default function App() {
  const [activeTab, setActiveTab] = useState<'Chat' | 'Cowork'>('Chat');
  const [inputValue, setInputValue] = useState(
    `Debug why payments are failing for customer Rahul Sharma.\n` +
    `PAN: ABCDE1234F  |  Email: rahul@example.com  |  Phone: +91 90000 12345\n` +
    `Prod DB: postgresql://admin:Sup3rS3cret@10.20.4.15:5432/customer_prod\n` +
    `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n` +
    `-----BEGIN RSA PRIVATE KEY-----\n` +
    `Our company plans to acquire ExampleCorp for ₹450 crore next quarter. The talks are confidential.\n` +
    `Internal doc: https://mycompany.atlassian.net/wiki/payments/roadmap\n` +
    `Aadhaar: 2345 6789 0123`
  );

  const navItems = [
    { label: 'Projects', icon: Folder },
    { label: 'Artifacts', icon: Layers },
    { label: 'Code', icon: Code2 },
    { label: 'Customize', icon: SlidersHorizontal },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#121214] text-[#FAFAFA] select-none font-['Inter',sans-serif]">

      {/* ── LEFT SIDEBAR ──────────────────────────────────────────────────── */}
      <aside
        id="sidebar-container"
        className="w-[280px] min-w-[280px] max-w-[280px] h-screen bg-[#171719] border-r border-[#252529] flex flex-col justify-between z-20 shrink-0 select-none"
      >
        <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col">

          {/* App name — generic */}
          <div
            id="sidebar-logo"
            className="pt-[20px] px-[16px] pb-[12px] text-[22px] font-[700] tracking-[-0.02em] text-white leading-none flex items-center gap-[10px]"
          >
            <div className="w-[28px] h-[28px] rounded-[8px] bg-gradient-to-br from-[#6C3AFF] to-[#0F62FE] grid place-items-center shrink-0">
              <MessageSquare className="w-[15px] h-[15px] text-white" />
            </div>
            <span>AI Chat</span>
          </div>

          {/* New chat button */}
          <div className="mx-[12px] mb-[10px]">
            <button
              id="new-chat-button"
              type="button"
              className="w-full h-[38px] bg-[#2A2A2E] hover:bg-[#323238] active:bg-[#252529] text-[#E4E4E7] text-[14px] font-medium rounded-[10px] flex items-center px-[12px] gap-[8px] transition-colors cursor-pointer"
            >
              <Plus className="w-[16px] h-[16px] stroke-[1.5] text-[#E4E4E7]" />
              <span className="leading-none">New chat</span>
            </button>
          </div>

          {/* Nav */}
          <nav id="sidebar-nav-list" className="px-[8px] flex flex-col space-y-[2px]">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <div
                  key={item.label}
                  id={`nav-item-${item.label.toLowerCase()}`}
                  className="h-[36px] px-[12px] py-[8px] flex items-center gap-[12px] rounded-[8px] hover:bg-[#202024] cursor-pointer transition-colors group"
                >
                  <Icon className="w-[18px] h-[18px] stroke-[1.5] text-[#A1A1AA] group-hover:text-[#D4D4D8] transition-colors" />
                  <span className="text-[14px] text-[#A1A1AA] group-hover:text-[#E4E4E7] font-normal leading-[20px] transition-colors">
                    {item.label}
                  </span>
                </div>
              );
            })}
          </nav>

          {/* Recent chats — placeholder only, no real history */}
          <div
            id="section-recent-header"
            className="mt-[32px] px-[16px] flex items-center justify-between text-[12px] font-medium text-[#71717A] tracking-[0.04em]"
          >
            <span>Recent</span>
          </div>

          <div id="recent-list" className="mt-[6px] px-[8px] pb-[16px] flex flex-col space-y-[1px]">
            {/* No real chat history — intentionally empty */}
            <div className="px-[12px] py-[8px] text-[12px] text-[#52525B] italic">
              No recent chats
            </div>
          </div>

        </div>

        {/* ── Bottom user bar ──────────────────────────────────────────────── */}
        <div className="shrink-0 bg-[#171719]">
          <div className="px-[8px] py-[4px]">
            <div id="sidebar-design-row" className="h-[36px] px-[12px] py-[8px] flex items-center gap-[12px] rounded-[8px] hover:bg-[#202024] cursor-pointer transition-colors group">
              <Palette className="w-[18px] h-[18px] stroke-[1.5] text-[#A1A1AA] group-hover:text-[#D4D4D8] transition-colors" />
              <span className="text-[14px] text-[#A1A1AA] font-normal group-hover:text-[#E4E4E7] transition-colors">Appearance</span>
            </div>
          </div>
          <div className="border-t border-[#232326]" />
          <div id="sidebar-user-bar" className="h-[52px] px-[12px] py-[10px] flex items-center justify-between">
            <div className="flex items-center gap-[10px] cursor-pointer group">
              <div id="user-avatar" className="w-[28px] h-[28px] rounded-full bg-[#2C2C30] flex items-center justify-center text-[11px] font-[600] text-white tracking-wide shrink-0 border border-[#38383D]">U</div>
              <span id="user-name" className="text-[13px] font-medium text-[#D4D4D8] group-hover:text-white transition-colors leading-none">User</span>
              <ChevronDown className="w-[12px] h-[12px] text-[#71717A] group-hover:text-[#A1A1AA] transition-colors" />
            </div>
            <div className="flex items-center gap-[10px]">
              <button id="user-search-btn" type="button" className="text-[#71717A] hover:text-[#A1A1AA] transition-colors p-[2px] cursor-pointer" title="Search">
                <Search className="w-[16px] h-[16px] stroke-[1.5]" />
              </button>
              <button id="user-panel-btn" type="button" className="text-[#71717A] hover:text-[#A1A1AA] transition-colors p-[2px] cursor-pointer" title="Collapse Panel">
                <PanelLeft className="w-[16px] h-[16px] stroke-[1.5]" />
              </button>
            </div>
          </div>
        </div>
      </aside>

      {/* ── MAIN CONTENT AREA ─────────────────────────────────────────────── */}
      <main id="main-content-area" className="flex-1 h-screen bg-[#121214] flex flex-col relative overflow-y-auto select-none">
        <div className="absolute top-[12px] right-[12px] z-30">
          <button id="top-right-help-icon" type="button" className="w-[28px] h-[28px] flex items-center justify-center text-white/80 hover:text-white transition-colors cursor-pointer" title="Help">
            <HelpCircle className="w-[20px] h-[20px] stroke-[1.5]" />
          </button>
        </div>

        <div className="flex-1 flex flex-col items-center justify-start pt-[10vh] px-4">

          {/* Hero greeting — generic */}
          <div id="hero-greeting-group" className="flex items-center justify-center gap-[12px] mb-[32px]">
            <div className="w-[40px] h-[40px] rounded-[12px] bg-gradient-to-br from-[#6C3AFF] to-[#0F62FE] grid place-items-center shadow-[0_4px_16px_rgba(108,58,255,0.4)]">
              <MessageSquare className="w-[20px] h-[20px] text-white" />
            </div>
            <h1 id="hero-heading" className="text-[40px] leading-[48px] font-[300] tracking-[-0.03em] text-[#FAFAFA] select-text">
              How can I help you?
            </h1>
          </div>

          {/* PromptShield extension */}
          <PromptShield value={inputValue} onApplyRedacted={setInputValue} onValueChange={setInputValue} />

          {/* Prompt input box */}
          <div
            id="prompt-input-container"
            className="w-[720px] max-w-[85%] min-h-[118px] bg-[#1E1E21] border border-[#2E2E32] rounded-[16px] shadow-[0_0_0_1px_rgba(0,0,0,0.2)] p-[16px_16px_12px_16px] flex flex-col justify-between focus-within:border-[#3E3E44] transition-all mt-3"
          >
            <div className="w-full">
              <textarea
                id="prompt-textarea"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                placeholder="Type your prompt here…"
                rows={3}
                className="w-full bg-transparent text-[15px] font-normal text-[#FAFAFA] placeholder-[#71717A] focus:outline-none font-['Inter',sans-serif] leading-[20px] resize-none"
              />
            </div>
            <div id="input-box-bottom-bar" className="flex items-center justify-between pt-[10px]">
              <div className="flex items-center gap-[8px]">
                <button id="input-add-button" type="button" className="w-[24px] h-[24px] rounded-full border border-[#3F3F46] hover:border-[#52525B] bg-transparent flex items-center justify-center text-[#A1A1AA] hover:text-white transition-colors cursor-pointer shrink-0" title="Attach file">
                  <Plus className="w-[14px] h-[14px] stroke-[2]" />
                </button>
                <div id="input-mode-tabs" className="flex items-center gap-[2px]">
                  <button id="tab-chat" type="button" onClick={() => setActiveTab('Chat')} className={`text-[13px] font-medium px-[12px] py-[6px] rounded-[8px] transition-colors cursor-pointer ${activeTab === 'Chat' ? 'bg-[#2D2D31] text-[#FFFFFF]' : 'text-[#71717A] hover:text-[#A1A1AA]'}`}>Chat</button>
                  <button id="tab-cowork" type="button" onClick={() => setActiveTab('Cowork')} className={`text-[13px] font-medium px-[12px] py-[6px] rounded-[8px] transition-colors cursor-pointer ${activeTab === 'Cowork' ? 'bg-[#2D2D31] text-[#FFFFFF]' : 'text-[#71717A] hover:text-[#A1A1AA]'}`}>Cowork</button>
                </div>
              </div>
              <div id="input-model-selector" className="flex items-center gap-[6px] text-[13px]">
                <div className="flex items-center gap-[6px] cursor-pointer hover:opacity-90 transition-opacity">
                  <span className="font-semibold text-[#E4E4E7]">AI Model</span>
                  <span className="text-[#71717A]">Protected</span>
                </div>
                <button id="mic-button" type="button" className="text-[#A1A1AA] hover:text-white transition-colors p-[3px] ml-[2px] cursor-pointer" title="Voice input">
                  <Mic className="w-[18px] h-[18px] stroke-[1.5]" />
                </button>
                <button id="model-dropdown-button" type="button" className="text-[#71717A] hover:text-[#A1A1AA] transition-colors p-[2px] cursor-pointer" title="Select Model">
                  <ChevronDown className="w-[14px] h-[14px]" />
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="pb-4 pt-2 text-center text-[11px] text-[#52525B] px-4">
          Ultron protects your data before it leaves your device.
        </div>
      </main>
    </div>
  );
}
