#include "../SDK/RegistryGuard.h"
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <deque>
#include <memory>
namespace {
constexpr COLORREF Ink=RGB(19,30,48),Blue=RGB(37,97,240),Paper=RGB(244,247,251),Muted=RGB(91,105,125);
HWND mainWindow{},pathBox{},list{},ruleList{},actionBox{};HFONT body{},title{};HBRUSH paper{},white{};bool preview=false,active=false;
RegistryGuard::Session session;std::vector<RG_RULE> rules;RG_STATS stats{};unsigned nextId=1;
std::wstring note=L"Ready. Audit first; add a scoped rule and start a session.";
void Text(HDC dc,int x,int y,const std::wstring& text,COLORREF color=Ink,HFONT font=nullptr){SetBkMode(dc,TRANSPARENT);SetTextColor(dc,color);SelectObject(dc,font?font:body);TextOutW(dc,x,y,text.c_str(),static_cast<int>(text.size()));}
void Card(HDC dc,RECT r){HBRUSH brush=CreateSolidBrush(RGB(255,255,255));auto old=SelectObject(dc,brush);auto pen=SelectObject(dc,GetStockObject(NULL_PEN));RoundRect(dc,r.left,r.top,r.right,r.bottom,14,14);SelectObject(dc,old);SelectObject(dc,pen);DeleteObject(brush);}
HWND Control(const wchar_t* type,const wchar_t* text,int id,DWORD style=0){auto h=CreateWindowExW(0,type,text,WS_CHILD|WS_VISIBLE|WS_TABSTOP|style,0,0,10,10,mainWindow,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),nullptr,nullptr);SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(body),TRUE);return h;}
void Button(const wchar_t* text,int id){Control(L"BUTTON",text,id,BS_OWNERDRAW);}
std::wstring Value(){std::array<wchar_t,32768> text{};GetWindowTextW(pathBox,text.data(),static_cast<int>(text.size()));return text.data();}
void Cell(int row,int col,const std::wstring& text){LVITEMW item{};item.mask=LVIF_TEXT;item.iItem=row;item.iSubItem=col;item.pszText=const_cast<wchar_t*>(text.c_str());if(col)ListView_SetItem(list,&item);else ListView_InsertItem(list,&item);}
void ReviewRules(){ListView_DeleteAllItems(ruleList);for(unsigned i=0;i<rules.size();++i){const auto& r=rules[i];std::wstring id=std::to_wstring(r.Id),action=r.Action?L"Deny":L"Audit",path(r.Path,r.Path+r.Chars);LVITEMW item{};item.mask=LVIF_TEXT;item.iItem=static_cast<int>(i);item.pszText=id.data();ListView_InsertItem(ruleList,&item);ListView_SetItemText(ruleList,static_cast<int>(i),1,action.data());ListView_SetItemText(ruleList,static_cast<int>(i),2,path.data());}}
void Event(const RG_EVENT& e){if(ListView_GetItemCount(list)>=400)ListView_DeleteItem(list,0);int row=ListView_GetItemCount(list);Cell(row,0,std::to_wstring(e.Sequence));Cell(row,1,std::to_wstring(e.ProcessId));Cell(row,2,e.Decision?L"DENIED":L"Observed");Cell(row,3,e.RuleId?std::to_wstring(e.RuleId):L"Default");Cell(row,4,RegistryGuard::Path(e));}
void Layout(){RECT r{};GetClientRect(mainWindow,&r);int w=r.right;
 MoveWindow(GetDlgItem(mainWindow,1),w-280,23,125,36,TRUE);MoveWindow(GetDlgItem(mainWindow,2),w-145,23,120,36,TRUE);
 MoveWindow(pathBox,24,240,w-326,34,TRUE);MoveWindow(actionBox,w-290,240,120,120,TRUE);MoveWindow(GetDlgItem(mainWindow,3),w-158,240,134,34,TRUE);
 MoveWindow(GetDlgItem(mainWindow,4),24,289,136,34,TRUE);MoveWindow(GetDlgItem(mainWindow,5),172,289,150,34,TRUE);MoveWindow(GetDlgItem(mainWindow,6),334,289,138,34,TRUE);MoveWindow(GetDlgItem(mainWindow,7),484,289,138,34,TRUE);
 MoveWindow(ruleList,24,355,w-48,100,TRUE);MoveWindow(list,24,504,w-48,std::max(100,static_cast<int>(r.bottom)-591),TRUE);
}
void Browse(){wchar_t path[32768]{};OPENFILENAMEW dialog{};dialog.lStructSize=sizeof(dialog);dialog.hwndOwner=mainWindow;dialog.lpstrFilter=L"Windows executable\0*.exe\0\0";dialog.lpstrFile=path;dialog.nMaxFile=32768;dialog.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;if(GetOpenFileNameW(&dialog))SetWindowTextW(pathBox,path);}
void Launch(){
 std::wstring path=Value();if(path.empty()||path.find(L'"')!=std::wstring::npos)throw std::invalid_argument("Choose an executable path first.");
 std::wstring command=L"\""+path+L"\"";STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION info{};
 if(!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&startup,&info))throw std::runtime_error("Test launch returned Windows error "+std::to_string(GetLastError())+". Check the live decision below.");
 CloseHandle(info.hThread);CloseHandle(info.hProcess);note=L"Test program launched directly by this application. Close it normally when finished.";
}
void Paint(HDC dc){RECT r{};GetClientRect(mainWindow,&r);FillRect(dc,&r,paper);RECT header{0,0,r.right,82};HBRUSH dark=CreateSolidBrush(Ink);FillRect(dc,&header,dark);DeleteObject(dark);
 Text(dc,24,15,L"RegistryGuard",RGB(255,255,255),title);Text(dc,25,49,preview?L"OFFLINE PREVIEW / synthetic records / no driver access":L"SUBRegistryGuard",RGB(195,210,232));
 int width=(r.right-72)/3;
 const std::array<std::wstring,3> labels{L"Events observed",L"Operations denied",L"Dropped log records"};const std::array<RG_U64,3> values{stats.Produced,stats.Denied,stats.Dropped};
 for(int i=0;i<3;++i){int x=24+i*(width+12);Card(dc,{x,98,x+width,180});Text(dc,x+16,110,labels[i],Muted);Text(dc,x+16,135,std::to_wstring(values[i]),Blue,title);}
 Text(dc,24,199,L"Native registry branch",Ink,title);Text(dc,24,218,L"First matching rule wins. Closing this application removes its policy.",Muted);
 Text(dc,24,329,L"Rules / evaluated in this order",Muted);Text(dc,24,469,L"Decision log",Ink,title);Text(dc,24,r.bottom-68,note,Muted);Text(dc,24,r.bottom-40,L"Engineering preview: Microsoft altitude, signing and kernel runtime qualification pending.",Muted);
}
LRESULT CALLBACK Proc(HWND h,UINT message,WPARAM w,LPARAM l){switch(message){
 case WM_CREATE:{mainWindow=h;body=CreateFontW(16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");title=CreateFontW(24,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");paper=CreateSolidBrush(Paper);white=CreateSolidBrush(RGB(255,255,255));
  Button(L"Start session",1);Button(L"Stop / restore",2);EnableWindow(GetDlgItem(h,2),FALSE);pathBox=Control(L"EDIT",L"\\REGISTRY\\MACHINE\\SOFTWARE\\TitanRegistryGuardDemo",10,WS_BORDER|ES_AUTOHSCROLL);SendMessageW(pathBox,EM_SETLIMITTEXT,32760,0);
  actionBox=Control(L"COMBOBOX",L"",11,CBS_DROPDOWNLIST);SendMessageW(actionBox,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(L"Audit"));SendMessageW(actionBox,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(L"Deny"));SendMessageW(actionBox,CB_SETCURSEL,0,0);
  Button(L"Add rule",3);Button(L"Clear rules",4);Button(L"Driver setup",5);Button(L"Browse .exe",6);Button(L"Test launch",7);
  ShowWindow(GetDlgItem(h,6),SW_HIDE);ShowWindow(GetDlgItem(h,7),SW_HIDE);
  ruleList=Control(WC_LISTVIEWW,L"",21,LVS_REPORT|LVS_SINGLESEL);ListView_SetExtendedListViewStyle(ruleList,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_LABELTIP);
  const std::array<std::pair<const wchar_t*,int>,3> ruleCols{{{L"ID",60},{L"Action",90},{L"Native rule path",800}}};for(unsigned i=0;i<ruleCols.size();++i){LVCOLUMNW col{};col.mask=LVCF_TEXT|LVCF_WIDTH;col.cx=ruleCols[i].second;col.pszText=const_cast<wchar_t*>(ruleCols[i].first);ListView_InsertColumn(ruleList,static_cast<int>(i),&col);}
  list=Control(WC_LISTVIEWW,L"",20,LVS_REPORT|LVS_SINGLESEL);ListView_SetExtendedListViewStyle(list,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_LABELTIP);
  const std::array<std::pair<const wchar_t*,int>,5> columns{{{L"Sequence",85},{L"Process",85},{L"Decision",105},{L"Rule",60},{L"Native path",600}}};for(unsigned i=0;i<columns.size();++i){LVCOLUMNW col{};col.mask=LVCF_TEXT|LVCF_WIDTH;col.cx=columns[i].second;col.pszText=const_cast<wchar_t*>(columns[i].first);ListView_InsertColumn(list,static_cast<int>(i),&col);}
  if(preview){note=L"Synthetic preview. Live operation requires a qualified Microsoft-signed driver package.";for(int id:{1,2,3,4,6,7})EnableWindow(GetDlgItem(h,id),FALSE);stats.Produced=36;stats.Denied=3;for(unsigned i=0;i<6;++i){RG_EVENT e{};e.Sequence=i+1;e.ProcessId=4242;e.RuleId=1;e.Decision=i%2;std::wstring name=L"\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\Product";e.Chars=static_cast<unsigned>(name.size());std::copy(name.begin(),name.end(),e.Path);Event(e);}}
  SetTimer(h,1,200,nullptr);Layout();return 0;}
 case WM_COMMAND:if(HIWORD(w)==BN_CLICKED)try{switch(LOWORD(w)){
  case 1:session.Start(rules);active=true;EnableWindow(GetDlgItem(h,1),FALSE);EnableWindow(GetDlgItem(h,2),TRUE);note=L"Session started. Rules affect supported user-mode registry writes.";break;
  case 2:session.Stop();active=false;EnableWindow(GetDlgItem(h,1),TRUE);EnableWindow(GetDlgItem(h,2),FALSE);note=L"Stopped. Policy removed.";break;
  case 3:{if(rules.size()==RG_RULES)throw std::invalid_argument("At most 16 rules are supported.");auto updated=rules;updated.push_back(RegistryGuard::Rule(nextId,Value(),SendMessageW(actionBox,CB_GETCURSEL,0,0)==1?RegistryGuard::Action::Deny:RegistryGuard::Action::Audit));if(active)session.SetRules(updated);rules.swap(updated);ReviewRules();++nextId;note=L"Rule added. Active rules: "+std::to_wstring(rules.size());break;}
  case 4:if(active)session.SetRules({});rules.clear();ReviewRules();note=L"Rules cleared. No deny policy is active.";break;
  case 5:{wchar_t file[32768]{};GetModuleFileNameW(nullptr,file,32768);std::wstring path=file;path=path.substr(0,path.find_last_of(L"\\/")+1)+L"RegistryGuardSetup.exe";if(reinterpret_cast<INT_PTR>(ShellExecuteW(h,L"runas",path.c_str(),nullptr,nullptr,SW_SHOWNORMAL))<=32)note=L"Setup is not included until driver qualification/signing is complete. Read README.md.";break;}
  case 6:Browse();break;case 7:Launch();break;
 }}catch(const std::exception& e){auto text=std::string(e.what());note=std::wstring(text.begin(),text.end());}InvalidateRect(h,nullptr,FALSE);return 0;
 case WM_TIMER:if(active)try{for(int n=0;n<4;++n){auto batch=session.Read();stats=batch.Stats;for(unsigned i=0;i<batch.Count;++i)Event(batch.Events[i]);if(batch.Count<RG_READ)break;}InvalidateRect(h,nullptr,FALSE);}catch(const std::exception& e){session.Stop();active=false;auto text=std::string(e.what());note=std::wstring(text.begin(),text.end());EnableWindow(GetDlgItem(h,1),TRUE);EnableWindow(GetDlgItem(h,2),FALSE);InvalidateRect(h,nullptr,FALSE);}return 0;
 case WM_DRAWITEM:{auto item=reinterpret_cast<DRAWITEMSTRUCT*>(l);bool primary=item->CtlID==1||item->CtlID==3;COLORREF fill=primary?Blue:RGB(255,255,255);if(item->itemState&ODS_SELECTED)fill=Ink;HBRUSH b=CreateSolidBrush(fill);FillRect(item->hDC,&item->rcItem,b);DeleteObject(b);wchar_t text[100]{};GetWindowTextW(item->hwndItem,text,100);SetBkMode(item->hDC,TRANSPARENT);SelectObject(item->hDC,body);SetTextColor(item->hDC,item->itemState&ODS_DISABLED?Muted:primary?RGB(255,255,255):Blue);DrawTextW(item->hDC,text,-1,&item->rcItem,DT_CENTER|DT_VCENTER|DT_SINGLELINE);if(item->itemState&ODS_FOCUS)DrawFocusRect(item->hDC,&item->rcItem);return TRUE;}
 case WM_SETCURSOR:{auto control=reinterpret_cast<HWND>(w);if(LOWORD(l)==HTCLIENT&&control!=h&&IsWindowEnabled(control)&&GetDlgCtrlID(control)>=1&&GetDlgCtrlID(control)<=7){SetCursor(LoadCursorW(nullptr,IDC_HAND));return TRUE;}break;}
 case WM_SIZE:Layout();InvalidateRect(h,nullptr,FALSE);return 0;
 case WM_GETMINMAXINFO:reinterpret_cast<MINMAXINFO*>(l)->ptMinTrackSize={1030,790};return 0;
 case WM_CTLCOLORSTATIC:case WM_CTLCOLOREDIT:SetTextColor(reinterpret_cast<HDC>(w),Ink);SetBkColor(reinterpret_cast<HDC>(w),RGB(255,255,255));return reinterpret_cast<LRESULT>(white);
 case WM_ERASEBKGND:return 1;
 case WM_PAINT:{PAINTSTRUCT ps{};auto dc=BeginPaint(h,&ps);RECT r{};GetClientRect(h,&r);auto memory=CreateCompatibleDC(dc);auto bitmap=CreateCompatibleBitmap(dc,std::max(1L,r.right),std::max(1L,r.bottom));auto old=SelectObject(memory,bitmap);Paint(memory);BitBlt(dc,0,0,r.right,r.bottom,memory,0,0,SRCCOPY);SelectObject(memory,old);DeleteObject(bitmap);DeleteDC(memory);EndPaint(h,&ps);return 0;}
 case WM_DESTROY:KillTimer(h,1);session.Stop();DeleteObject(body);DeleteObject(title);DeleteObject(paper);DeleteObject(white);PostQuitMessage(0);return 0;
 }return DefWindowProcW(h,message,w,l);}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int show){int count=0;auto args=CommandLineToArgvW(GetCommandLineW(),&count);for(int i=1;args&&i<count;++i)if(wcscmp(args[i],L"--preview")==0)preview=true;if(args)LocalFree(args);SetProcessDPIAware();INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_LISTVIEW_CLASSES};InitCommonControlsEx(&controls);WNDCLASSEXW cls{};cls.cbSize=sizeof(cls);cls.hInstance=instance;cls.lpfnWndProc=Proc;cls.lpszClassName=L"RegistryGuardWindow";cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);if(!RegisterClassExW(&cls))return 1;auto h=CreateWindowExW(0,cls.lpszClassName,L"RegistryGuard",WS_OVERLAPPEDWINDOW,100,100,1120,820,nullptr,nullptr,instance,nullptr);if(!h)return 1;ShowWindow(h,show);MSG message{};while(GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(h,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}return 0;}
