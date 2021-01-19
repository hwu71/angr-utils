import networkx

from collections import defaultdict

from bingraphvis import *
from bingraphvis.angr import *
from bingraphvis.angr.x86 import *

def set_plot_style(c):
    set_style(c)

def plot_common(graph, fname, format="png", type=True):
    vis = AngrVisFactory().default_common_graph_pipeline(type=type)
    vis.set_output(DotOutput(fname, format=format))
    vis.process(graph)

def plot_cfg(cfg, fname, format="png", state=None, asminst=False, vexinst=False, func_addr=None, remove_imports=True, remove_path_terminator=True, remove_simprocedures=False, debug_info=False, comments=True, color_depth=False, special_nodes=None):
    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=asminst, vexinst=vexinst, comments=comments)
    if remove_imports:
        vis.add_transformer(AngrRemoveImports(cfg.project))
    if remove_simprocedures:
        vis.add_transformer(AngrRemoveSimProcedures())
    if func_addr:
        vis.add_transformer(AngrFilterNodes(lambda node: node.obj.function_address in func_addr and func_addr[node.obj.function_address]))
    if debug_info:
        vis.add_content(AngrCFGDebugInfo())
    if state:
        vis.add_edge_annotator(AngrPathAnnotator(state))
        vis.add_node_annotator(AngrPathAnnotator(state))
    if color_depth:
        vis.add_clusterer(AngrCallstackKeyClusterer())
        vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    if special_nodes:
        vis.add_node_annotator(AngrColorCFGNodes(special_nodes))
    vis.set_output(DotOutput(fname, format=format))    
    vis.process(cfg.graph) 

def plot_func_graph(project, graph, fname, format="png", asminst=True, ailinst=True, vexinst=False, structure=None, color_depth=False):
    vis = AngrVisFactory().default_func_graph_pipeline(project, asminst=asminst, ailinst=ailinst, vexinst=vexinst)
    if structure:
        vis.add_clusterer(AngrStructuredClusterer(structure))
        if color_depth:
            vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    vis.set_output(DotOutput(fname, format=format))
    vis.process(graph) 

#Note: method signature may be changed in the future
def plot_structured_graph(project, structure, fname, format="png", asminst=True, ailinst=True, vexinst=False, color_depth=False):
    vis = AngrVisFactory().default_structured_graph_pipeline(project, asminst=asminst, ailinst=ailinst, vexinst=vexinst)
    if color_depth:
        vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    vis.set_output(DotOutput(fname, format=format))
    vis.process(structure)

def plot_cg(kb, fname, format="png", verbose=False, filter=None):
    vis = AngrVisFactory().default_cg_pipeline(kb, verbose=verbose)
    vis.set_output(DotOutput(fname, format=format))
    vis.process(kb, filter)
    
def plot_cdg(cfg, cdg, fname, format="png", pd_edges=False, cg_edges=True, remove_fakeret=True):
    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=True, vexinst=False, color_edges=False)
    if remove_fakeret:
        vis.add_transformer(AngrRemoveFakeretEdges())
    if pd_edges:
        vis.add_transformer(AngrAddEdges(cdg.get_post_dominators(), color="green", reverse=True))
    if cg_edges:
        vis.add_transformer(AngrAddEdges(cdg.graph, color="purple", reverse=False))
    vis.set_output(DotOutput(fname, format=format))
    vis.process(cfg.graph)

def plot_dfg(dfg, fname, format="png"):
    vis = AngrVisFactory().default_common_graph_pipeline(type=True)
    vis.set_output(DotOutput(fname, format=format))
    vis.process(dfg)

#Note: method signature may change in the future
def plot_ddg_stmt(ddg_stmt, fname, format="png", project=None):
    vis = AngrVisFactory().default_common_graph_pipeline()
    if project:
        vis.add_content(AngrAsm(project))
        vis.add_content(AngrVex(project))
    vis.add_edge_annotator(AngrColorDDGStmtEdges(project))
    vis.set_output(DotOutput(fname, format=format))
    vis.process(ddg_stmt)

#Note: method signature may change in the future
def plot_ddg_data(ddg_data, fname, format="png", project=None, asminst=False, vexinst=True):
    vis = Vis()
    vis.set_source(AngrCommonSource())
    vis.add_content(AngrDDGLocationHead())
    vis.add_content(AngrDDGVariableHead(project=project))

    if project:
        if asminst:
            vis.add_content(AngrAsm(project))
        if vexinst:
            vis.add_content(AngrVex(project))
    acd = AngrColorDDGData(project, labels=True)
    vis.add_edge_annotator(acd)
    vis.add_node_annotator(acd)
    vis.set_output(DotOutput(fname, format=format))
    vis.process(ddg_data)

def plot_pdg(pdg, fname, format="png", project=None, directly_affected_stmts=None, indirectly_affected_stmts=None):
    vis = AngrVisFactory().default_common_graph_pipeline()
    if project:
        vis.add_content(AngrAsm(project))
        vis.add_content(AngrVex(project))
    if directly_affected_stmts is not None and indirectly_affected_stmts is not None:
        vis.add_node_annotator(AngrColorPDGNodes(project, directly_affected_stmts, indirectly_affected_stmts))
    vis.add_edge_annotator(AngrColorPDGEdges(project))
    vis.set_output(DotOutput(fname, format=format))
    vis.process(pdg)
    
def plot_affected_stmts_in_cfg(cfg, fname, format="png", state=None, 
                               asminst=False, vexinst=True, func_addr=None, 
                               remove_imports=True, remove_path_terminator=True,
                               remove_simprocedures=False, debug_info=False, 
                               comments=True, color_depth=False, 
                               directly_affected_stmts=None, indirectly_affected_stmts=None):
    if directly_affected_stmts is None and indirectly_affected_stmts is None:
        print("<directly_affected_stmts> and <indirectly_affected_stmts> are required.")
        return 
    if vexinst is not True:
        print("<vexinst> must set to True")
        return
    directly_affected_stmts_dict = {}
    indirectly_affected_stmts_dict = {}
    
    if directly_affected_stmts is not None:
        for (irsb, stmt_idx) in directly_affected_stmts:
            if irsb.addr not in directly_affected_stmts_dict:
                directly_affected_stmts_dict[irsb.addr] = []
            directly_affected_stmts_dict[irsb.addr].append(stmt_idx)

    if indirectly_affected_stmts is not None:
        for (irsb, stmt_idx) in indirectly_affected_stmts:
            if irsb.addr not in indirectly_affected_stmts_dict:
                indirectly_affected_stmts_dict[irsb.addr] = []
            indirectly_affected_stmts_dict[irsb.addr].append(stmt_idx)
            
    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=asminst, vexinst=vexinst, comments=comments, 
                                                directly_affected_stmts_dict=directly_affected_stmts_dict, 
                                                indirectly_affected_stmts_dict=indirectly_affected_stmts_dict)
    if remove_imports:
        vis.add_transformer(AngrRemoveImports(cfg.project))
    if remove_simprocedures:
        vis.add_transformer(AngrRemoveSimProcedures())
    if func_addr:
        vis.add_transformer(AngrFilterNodes(lambda node: node.obj.function_address in func_addr and func_addr[node.obj.function_address]))
    if debug_info:
        vis.add_content(AngrCFGDebugInfo())
    if state:
        vis.add_edge_annotator(AngrPathAnnotator(state))
        vis.add_node_annotator(AngrPathAnnotator(state))
    if color_depth:
        vis.add_clusterer(AngrCallstackKeyClusterer())
        vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    vis.set_output(DotOutput(fname, format=format))    
    vis.process(cfg.graph)
    
def plot_affected_ins_in_cfg(cfg, fname, format="png", state=None, 
                               asminst=True, vexinst=False, func_addr=None, 
                               remove_imports=True, remove_path_terminator=True,
                               remove_simprocedures=False, debug_info=False, 
                               comments=True, color_depth=False, 
                               directly_affected_ins_addrs=None, indirectly_affected_ins_addrs=None):
    if directly_affected_ins_addrs is None and indirectly_affected_ins_addrs is None:
        print("<directly_affected_ins_addrs> and <indirectly_affected_ins_addrs> are required.")
        return 
    
    if asminst is not True:
        print("<asminst> must set to True")
        return
    
    print("\ndirectly_affected_ins_addrs:", directly_affected_ins_addrs)
    print("\nindirectly_affected_ins_addrs:", indirectly_affected_ins_addrs)

    vis = AngrVisFactory().default_cfg_pipeline(cfg, asminst=asminst, vexinst=vexinst, comments=comments, 
                                                directly_affected_ins_addrs=directly_affected_ins_addrs, 
                                                indirectly_affected_ins_addrs=indirectly_affected_ins_addrs)
    if remove_imports:
        vis.add_transformer(AngrRemoveImports(cfg.project))
    if remove_simprocedures:
        vis.add_transformer(AngrRemoveSimProcedures())
    if func_addr:
        vis.add_transformer(AngrFilterNodes(lambda node: node.obj.function_address in func_addr and func_addr[node.obj.function_address]))
    if debug_info:
        vis.add_content(AngrCFGDebugInfo())
    if state:
        vis.add_edge_annotator(AngrPathAnnotator(state))
        vis.add_node_annotator(AngrPathAnnotator(state))
    if color_depth:
        vis.add_clusterer(AngrCallstackKeyClusterer())
        vis.add_clusterer(ColorDepthClusterer(palette='greens'))
    vis.set_output(DotOutput(fname, format=format))    
    vis.process(cfg.graph)