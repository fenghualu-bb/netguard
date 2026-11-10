"""Exercise real Tk layout at Windows DPI, using offline snapshots only."""
import ctypes
import json
import sys
from test_workbench import wb, snapshot
from unittest.mock import patch

ctypes.windll.shcore.SetProcessDpiAwareness(1)
dpi = int(sys.argv[1]) if len(sys.argv)>1 else None
original_init = wb.tk.Tk.__init__
def scaled_init(self,*args,**kwargs):
    original_init(self,*args,**kwargs)
    if dpi: self.tk.call('tk','scaling',dpi/72)
with patch.object(wb.tk.Tk,'__init__',scaled_init), patch.object(wb, 'collect', return_value=snapshot()):
    app = wb.Workbench()
    app.withdraw()
    app.update()
    result = {'pixels_per_inch': round(app.winfo_fpixels('1i')), 'windows': []}
    def buttons(root):
        found=[]
        def walk(widget):
            # 只检查当前可见页面上的按钮（隐藏页面的按钮不在屏幕上）
            if widget.winfo_class() == 'TButton' and widget.winfo_viewable(): found.append(widget)
            for child in widget.winfo_children(): walk(child)
        walk(root)
        return found
    def check(root, title):
        root.update_idletasks()
        height,width=root.winfo_height(),root.winfo_width()
        actual=[]
        for b in buttons(root):
            x=b.winfo_rootx()-root.winfo_rootx()
            y=b.winfo_rooty()-root.winfo_rooty()
            # 滚动区里的按钮：水平方向必须在窗内，竖直方向只要求能滚到（在 scrollregion 内）
            canvas=b.master
            while canvas is not None and canvas.winfo_class()!='Canvas': canvas=canvas.master
            if canvas is not None:
                region=[float(v) for v in str(canvas.cget('scrollregion')).split()] or [0,0,0,0]
                inner_y=b.winfo_rooty()-canvas.winfo_rooty()+canvas.canvasy(0)
                fits=x>=0 and x+b.winfo_width()<=width and region[1]<=inner_y and inner_y+b.winfo_height()<=region[3]+1
                kind='scroll'
            else:
                fits=x>=0 and y>=0 and x+b.winfo_width()<=width and y+b.winfo_height()<=height
                kind='fixed'
            actual.append({'label':b.cget('text'),'area':kind,'inside':fits})
        result['windows'].append({'title':title,'size':[width,height],'buttons':actual})
        assert all(b['inside'] for b in actual), result['windows'][-1]
    try:
        # Keep windows mapped so geometry is real, without a network action.
        app.deiconify()
        app.update()
        for page in ('overview', 'records', 'maintenance'):
            app.show_page(page); app.update()
            check(app, 'workbench/' + page)
        app.geometry(f'{app.winfo_width()}x{int(app.winfo_fpixels("4i"))}')
        for page in ('overview', 'records', 'maintenance'):
            app.show_page(page); app.update()
            check(app, 'short window/' + page)
        app.show_page('overview')
        for leaving in (False,True):
            wizard=wb.RealIpWizard(app,leaving)
            wizard.update()
            check(wizard,'leave wizard' if leaving else 'enter wizard')
            wizard.destroy()
    finally:
        app.destroy()
print(json.dumps(result,ensure_ascii=False,indent=2))
