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
  Download,
  PanelLeft,
  Mic,
  HelpCircle,
} from 'lucide-react';
import PromptShield from './components/PromptShield';

export default function App() {
  const [activeTab, setActiveTab] = useState<'Chat' | 'Cowork'>('Chat');
  const [inputValue, setInputValue] = useState('Hey fix this, my email arjun@gmail.com, also my PAN ABCDE1234F and internal doc https://mycompany.atlassian.net/wiki/secret-page — my manager at Infosys said my salary is 12LPA');

  const navItems = [
    { label: 'Projects', icon: Folder, upgrade: false },
    { label: 'Artifacts', icon: Layers, upgrade: false },
    { label: 'Code', icon: Code2, upgrade: true },
    { label: 'Customize', icon: SlidersHorizontal, upgrade: false },
  ];

  const projects = ['CruxLabx', 'Nadi-Pariksha'];

  const pinnedItems = [
    'Inspiring CSE juniors with AI and a',
    'Cooking ideas',
    'Building email outreach for US cli',
    'Website redesign with motion eff',
    'Hyperwrike',
    'Faceless AI YouTube channel mor',
    'Distribution moats matter more t',
    'IntraMind demo and collaboration',
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#121214] text-[#FAFAFA] select-none font-['Inter',sans-serif]">
      {/* LEFT SIDEBAR — 100% original Claude, no tags */}
      <aside
        id="sidebar-container"
        className="w-[280px] min-w-[280px] max-w-[280px] h-screen bg-[#171719] border-r border-[#252529] flex flex-col justify-between z-20 shrink-0 select-none"
      >
        <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col">
          <div
            id="sidebar-logo"
            className="pt-[20px] px-[16px] pb-[12px] font-claude-serif text-[22px] font-[600] tracking-[-0.02em] text-white leading-none flex items-center justify-between"
          >
            <span>Claude</span>
          </div>

          <div className="mx-[12px] mb-[10px]">
            <button
              id="new-chat-button"
              type="button"
              className="w-full h-[38px] bg-[#2A2A2E] hover:bg-[#323238] active:bg-[#252529] text-[#E4E4E7] text-[14px] font-medium rounded-[10px] flex items-center px-[12px] gap-[8px] transition-colors cursor-pointer"
            >
              <Plus className="w-[16px] h-[16px] stroke-[1.5] text-[#E4E4E7]" />
              <span className="leading-none">New</span>
            </button>
          </div>

          <nav id="sidebar-nav-list" className="px-[8px] flex flex-col space-y-[2px]">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <div
                  key={item.label}
                  id={`nav-item-${item.label.toLowerCase()}`}
                  className="h-[36px] px-[12px] py-[8px] flex items-center justify-between rounded-[8px] hover:bg-[#202024] cursor-pointer transition-colors group"
                >
                  <div className="flex items-center gap-[12px]">
                    <Icon className="w-[18px] h-[18px] stroke-[1.5] text-[#A1A1AA] group-hover:text-[#D4D4D8] transition-colors" />
                    <span className="text-[14px] text-[#A1A1AA] group-hover:text-[#E4E4E7] font-normal leading-[20px] transition-colors">
                      {item.label}
                    </span>
                  </div>
                  {item.upgrade && (
                    <span
                      id="pill-upgrade"
                      className="bg-[#1E293B0D] border border-[#253141] text-[#60A5FA] text-[12px] font-medium px-[9px] py-[2px] rounded-full leading-tight"
                    >
                      Upgrade
                    </span>
                  )}
                </div>
              );
            })}
          </nav>

          <div
            id="section-projects-header"
            className="mt-[32px] px-[16px] flex items-center justify-between text-[12px] font-medium text-[#71717A] tracking-[0.04em]"
          >
            <span>Projects</span>
            <button id="add-project-btn" type="button" className="p-[2px] hover:text-[#A1A1AA] transition-colors cursor-pointer" title="Add Project">
              <Plus className="w-[14px] h-[14px] text-[#71717A]" />
            </button>
          </div>

          <div id="projects-list" className="mt-[6px] px-[8px] flex flex-col space-y-[1px]">
            {projects.map((proj) => (
              <div key={proj} id={`project-item-${proj.toLowerCase()}`} className="h-[32px] px-[12px] py-[6px] flex items-center gap-[12px] rounded-[8px] hover:bg-[#202024] cursor-pointer transition-colors group">
                <Folder className="w-[18px] h-[18px] stroke-[1.5] text-[#A1A1AA] group-hover:text-[#D4D4D8] transition-colors" />
                <span className="text-[14px] text-[#D4D4D8] font-normal truncate group-hover:text-white transition-colors">{proj}</span>
              </div>
            ))}
          </div>

          <div id="section-pinned-header" className="mt-[28px] px-[16px] flex items-center justify-between text-[12px] font-medium text-[#71717A] tracking-[0.04em]">
            <span>Pinned</span>
            <button id="add-pinned-btn" type="button" className="p-[2px] hover:text-[#A1A1AA] transition-colors cursor-pointer" title="Add Pinned">
              <Plus className="w-[14px] h-[14px] text-[#71717A]" />
            </button>
          </div>

          <div id="pinned-list" className="mt-[6px] px-[8px] pb-[16px] flex flex-col space-y-[1px]">
            {pinnedItems.map((item, idx) => (
              <div key={idx} id={`pinned-item-${idx}`} className="h-[32px] px-[12px] py-[6px] flex items-center gap-[12px] rounded-[8px] hover:bg-[#202024] cursor-pointer transition-colors group" title={item}>
                <div className="w-[6px] h-[6px] rounded-full border border-[#52525B] shrink-0 group-hover:border-[#71717A] transition-colors" />
                <span className="text-[13.5px] text-[#A1A1AA] font-normal truncate group-hover:text-[#E4E4E7] transition-colors whitespace-nowrap overflow-hidden text-ellipsis">{item}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="shrink-0 bg-[#171719]">
          <div className="px-[8px] py-[4px]">
            <div id="sidebar-design-row" className="h-[36px] px-[12px] py-[8px] flex items-center gap-[12px] rounded-[8px] hover:bg-[#202024] cursor-pointer transition-colors group">
              <Palette className="w-[18px] h-[18px] stroke-[1.5] text-[#A1A1AA] group-hover:text-[#D4D4D8] transition-colors" />
              <span className="text-[14px] text-[#A1A1AA] font-normal group-hover:text-[#E4E4E7] transition-colors">Design</span>
            </div>
          </div>
          <div className="border-t border-[#232326]" />
          <div id="sidebar-user-bar" className="h-[52px] px-[12px] py-[10px] flex items-center justify-between">
            <div className="flex items-center gap-[10px] cursor-pointer group">
              <div id="user-avatar" className="w-[28px] h-[28px] rounded-full bg-[#2C2C30] flex items-center justify-center text-[11px] font-[600] text-white tracking-wide shrink-0 border border-[#38383D]">MK</div>
              <span id="user-name" className="text-[13px] font-medium text-[#D4D4D8] group-hover:text-white transition-colors leading-none">Commander</span>
              <ChevronDown className="w-[12px] h-[12px] text-[#71717A] group-hover:text-[#A1A1AA] transition-colors" />
            </div>
            <div className="flex items-center gap-[10px]">
              <button id="user-download-btn" type="button" className="text-[#71717A] hover:text-[#A1A1AA] transition-colors p-[2px] cursor-pointer" title="Download App"><Download className="w-[16px] h-[16px] stroke-[1.5]" /></button>
              <button id="user-search-btn" type="button" className="text-[#71717A] hover:text-[#A1A1AA] transition-colors p-[2px] cursor-pointer" title="Search"><Search className="w-[16px] h-[16px] stroke-[1.5]" /></button>
              <button id="user-panel-btn" type="button" className="text-[#71717A] hover:text-[#A1A1AA] transition-colors p-[2px] cursor-pointer" title="Collapse Panel"><PanelLeft className="w-[16px] h-[16px] stroke-[1.5]" /></button>
            </div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA — 100% original */}
      <main id="main-content-area" className="flex-1 h-screen bg-[#121214] flex flex-col relative overflow-y-auto select-none">
        <div className="absolute top-[12px] right-[12px] z-30">
          <button id="top-right-help-icon" type="button" className="w-[28px] h-[28px] flex items-center justify-center text-white/80 hover:text-white transition-colors cursor-pointer" title="Help and Support">
            <HelpCircle className="w-[20px] h-[20px] stroke-[1.5]" />
          </button>
        </div>

        <div className="w-full flex justify-center pt-[24px] z-20">
          <div id="top-plan-pill" className="bg-[#1A1A1E] border border-[#27272A] rounded-full px-[14px] py-[6px] text-[13px] flex items-center gap-[6px] shadow-sm hover:border-[#38383F] transition-colors cursor-pointer">
            <span className="text-[#9CA3AF] font-normal">Free plan</span>
            <span className="text-[#52525B] font-bold">·</span>
            <span className="text-[#93C5FD] underline font-medium hover:text-[#BFDBFE] transition-colors">Upgrade</span>
          </div>
        </div>

        <div className="flex-1 flex flex-col items-center justify-start pt-[8vh] px-4">
          <div id="hero-greeting-group" className="flex items-center justify-center gap-[10px] mb-[32px]">
            <svg id="claude-starburst-icon" className="w-[32px] h-[32px] text-[#E78A5E] shrink-0" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C12.45 2 12.8 2.35 12.8 2.8V6.2C14.8 6.6 16.5 7.8 17.5 9.5L19.9 7.1C20.2 6.8 20.7 6.8 21 7.1C21.3 7.4 21.3 7.9 21 8.2L18.6 10.6C19.3 11.8 19.8 13.2 19.8 14.7C19.8 15.15 19.45 15.5 19 15.5C18.55 15.5 18.2 15.15 18.2 14.7C18.2 11.28 15.42 8.5 12 8.5C11.55 8.5 11.2 8.15 11.2 7.7C11.2 7.25 11.55 6.9 12 6.9V2.8C12 2.35 12.35 2 12 2Z" opacity="0" />
              <rect x="10.5" y="2" width="3" height="20" rx="1.5" />
              <rect x="2" y="10.5" width="20" height="3" rx="1.5" />
              <rect x="10.5" y="2" width="3" height="20" rx="1.5" transform="rotate(45 12 12)" />
              <rect x="10.5" y="2" width="3" height="20" rx="1.5" transform="rotate(-45 12 12)" />
            </svg>
            <h1 id="hero-heading" className="font-claude-serif text-[42px] leading-[48px] font-[300] tracking-[-0.03em] text-[#FAFAFA] select-text">Good evening, Commander</h1>
          </div>

          {/* === EXTENSION — sits just beside typing area, no Muse UI changed === */}
          <PromptShield value={inputValue} onApplyRedacted={setInputValue} onValueChange={setInputValue} />

          {/* Input Box — 100% original Muse styling */}
          <div
            id="prompt-input-container"
            className="w-[720px] max-w-[85%] min-h-[118px] bg-[#1E1E21] border border-[#2E2E32] rounded-[16px] shadow-[0_0_0_1px_rgba(0,0,0,0.2)] p-[16px_16px_12px_16px] flex flex-col justify-between focus-within:border-[#3E3E44] transition-all mt-3"
          >
            <div className="w-full">
              <textarea
                id="prompt-textarea"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                placeholder="How can I help you today?"
                rows={3}
                className="w-full bg-transparent text-[15px] font-normal text-[#FAFAFA] placeholder-[#71717A] focus:outline-none font-['Inter',sans-serif] leading-[20px] resize-none"
              />
            </div>
            <div id="input-box-bottom-bar" className="flex items-center justify-between pt-[10px]">
              <div className="flex items-center gap-[8px]">
                <button id="input-add-button" type="button" className="w-[24px] h-[24px] rounded-full border border-[#3F3F46] hover:border-[#52525B] bg-transparent flex items-center justify-center text-[#A1A1AA] hover:text-white transition-colors cursor-pointer shrink-0" title="Attach file or context"><Plus className="w-[14px] h-[14px] stroke-[2]" /></button>
                <div id="input-mode-tabs" className="flex items-center gap-[2px]">
                  <button id="tab-chat" type="button" onClick={() => setActiveTab('Chat')} className={`text-[13px] font-medium px-[12px] py-[6px] rounded-[8px] transition-colors cursor-pointer ${activeTab === 'Chat' ? 'bg-[#2D2D31] text-[#FFFFFF]' : 'text-[#71717A] hover:text-[#A1A1AA]'}`}>Chat</button>
                  <button id="tab-cowork" type="button" onClick={() => setActiveTab('Cowork')} className={`text-[13px] font-medium px-[12px] py-[6px] rounded-[8px] transition-colors cursor-pointer ${activeTab === 'Cowork' ? 'bg-[#2D2D31] text-[#FFFFFF]' : 'text-[#71717A] hover:text-[#A1A1AA]'}`}>Cowork</button>
                </div>
              </div>
              <div id="input-model-selector" className="flex items-center gap-[6px] text-[13px]">
                <div className="flex items-center gap-[6px] cursor-pointer hover:opacity-90 transition-opacity">
                  <span className="font-semibold text-[#E4E4E7]">Sonnet 5</span><span className="text-[#71717A]">Medium</span>
                </div>
                <button id="mic-button" type="button" className="text-[#A1A1AA] hover:text-white transition-colors p-[3px] ml-[2px] cursor-pointer" title="Voice input"><Mic className="w-[18px] h-[18px] stroke-[1.5]" /></button>
                <button id="model-dropdown-button" type="button" className="text-[#71717A] hover:text-[#A1A1AA] transition-colors p-[2px] cursor-pointer" title="Select Model"><ChevronDown className="w-[14px] h-[14px]" /></button>
              </div>
            </div>
          </div>
        </div>

        <div className="pb-4 pt-2 text-center text-[11px] text-[#52525B] px-4">Claude can make mistakes. Please double-check responses.</div>
      </main>
    </div>
  );
}
