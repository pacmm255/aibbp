import esprima
import re

class Parser:

    @staticmethod
    def find_var_definition(var_name, start_line, code):
        code_lines = code.splitlines()

        relevant_code = '\n'.join(code_lines[:start_line - 1])

        sub_ast = esprima.parseScript(relevant_code, {'loc': True, 'range': True, 'tolerant': True})

        var_defs = {}

        def collect_var_defs(node, var_defs):
            if (node.type == 'VariableDeclarator' and 
                hasattr(node, 'id') and node.id and 
                hasattr(node, 'init') and node.init and 
                hasattr(node, 'loc') and node.loc):
                id_name = node.id.name if hasattr(node.id, 'name') else None
                if not id_name:
                    return
                abs_line = node.loc.start.line if hasattr(node.loc.start, 'line') else None
                if abs_line is None or abs_line >= start_line:
                    return
                if hasattr(node.init, 'range'):
                    value = relevant_code[node.init.range[0]:node.init.range[1]].strip()
                else:
                    value = str(node.init).strip() if node.init else ''
                if id_name not in var_defs:
                    var_defs[id_name] = []
                var_defs[id_name].append({'line': abs_line, 'value': value})

        def iterative_traverse(ast, visitor):
            if not ast:
                return
            stack = [ast]
            visited = set()
            max_stack_size = 10000

            while stack:
                if len(stack) > max_stack_size:
                    break
                node = stack.pop()
                node_id = id(node)
                if node_id in visited:
                    continue
                visited.add(node_id)

                visitor(node)
                for key in reversed(node.__dict__.keys()):
                    value = getattr(node, key, None)
                    if isinstance(value, list):
                        for item in reversed(value):
                            if isinstance(item, esprima.nodes.Node) and id(item) not in visited:
                                item._parent = node
                                stack.append(item)
                    elif isinstance(value, esprima.nodes.Node) and id(value) not in visited:
                        value._parent = node
                        stack.append(value)

        iterative_traverse(sub_ast, lambda n: collect_var_defs(n, var_defs))

        last_resolved = None
        def_line = None

        if var_name in var_defs:
            var_defs[var_name].sort(key=lambda x: x['line'], reverse=True)

            for defn in var_defs[var_name]:
                if 'btoa' not in defn['value'] and 'XOR_STR' not in defn['value'] and \
                'doubleXOR' not in defn['value'] and 'singlebtoa' not in defn['value']:
                    last_resolved = defn['value']
                    def_line = defn['line']
                    break

            if last_resolved:
                resolved_vars_cache = {}

                def resolve_var_recursive(expr, var_line):
                    try:
                        expr_ast = esprima.parseScript(expr, {'loc': True, 'range': True, 'tolerant': True})
                    except Exception:
                        return expr

                    vars_set = set()

                    def collect_identifiers(node):
                        if (hasattr(node, 'type') and node.type == 'Identifier' and 
                            hasattr(node, 'name')):
                            parent = getattr(node, '_parent', None)
                            if parent:
                                parent_type = parent.type if hasattr(parent, 'type') else None
                                if ((parent_type == 'MemberExpression' and 
                                    hasattr(parent, 'property') and parent.property == node and 
                                    not (hasattr(parent, 'computed') and parent.computed)) or
                                    (parent_type == 'ObjectProperty' and 
                                    hasattr(parent, 'key') and parent.key == node and 
                                    not (hasattr(parent, 'computed') and parent.computed)) or
                                    (parent_type == 'VariableDeclarator' and 
                                    hasattr(parent, 'id') and parent.id == node) or
                                    (parent_type == 'FunctionDeclaration' and 
                                    hasattr(parent, 'id') and parent.id == node) or
                                    (parent_type == 'FunctionExpression' and 
                                    hasattr(parent, 'id') and parent.id == node) or
                                    node.name == 'window'):
                                    return
                            vars_set.add(node.name)

                    def iterative_traverse_safe(ast, visitor):
                        if not ast:
                            return
                        stack = [ast]
                        visited = set()
                        while stack:
                            node = stack.pop()
                            node_id = id(node)
                            if node_id in visited:
                                continue
                            visited.add(node_id)
                            visitor(node)
                            for key in reversed(node.__dict__.keys()):
                                value = getattr(node, key, None)
                                if isinstance(value, list):
                                    for item in reversed(value):
                                        if isinstance(item, esprima.nodes.Node) and id(item) not in visited:
                                            item._parent = node
                                            stack.append(item)
                                elif isinstance(value, esprima.nodes.Node) and id(value) not in visited:
                                    value._parent = node
                                    stack.append(value)

                    iterative_traverse_safe(expr_ast, collect_identifiers)

                    if not vars_set:
                        return expr

                    for v in vars_set:
                        if v in resolved_vars_cache:
                            continue

                        def_value = v
                        if v in var_defs:
                            for defn in sorted(var_defs[v], key=lambda x: x['line'], reverse=True):
                                if defn['line'] < var_line and \
                                'btoa' not in defn['value'] and 'XOR_STR' not in defn['value'] and \
                                'doubleXOR' not in defn['value'] and 'singlebtoa' not in defn['value']:
                                    def_value = defn['value']
                                    break

                        resolved_vars_cache[v] = def_value
                        resolved_vars_cache[v] = resolve_var_recursive(def_value, var_line)

                    final_expr = expr
                    for k, v in resolved_vars_cache.items():
                        final_expr = re.sub(r'\b' + re.escape(k) + r'\b', str(v), final_expr)

                    return final_expr

                last_resolved = resolve_var_recursive(last_resolved, def_line)

                if last_resolved:
                    escaped_var_name = re.escape(var_name)

                    double_xor_pattern = re.compile(rf'XOR_STR\s*\(\s*{escaped_var_name}\s*,\s*{escaped_var_name}\s*\)')
                    xor_matches = double_xor_pattern.findall(code)

                    if xor_matches and len(xor_matches) >= 2:
                        last_resolved = f'doublexor({last_resolved})'
                    else:

                        usage_line_index = start_line - 1
                        search_start = max(0, usage_line_index - 10)
                        relevant_lines = '\n'.join(code_lines[search_start:usage_line_index + 1])

                        btoa_pattern = re.compile(rf'btoa\s*\(\s*""\s*\+\s*{escaped_var_name}\s*\)')
                        xor_var_pattern = re.compile(rf'XOR_STR\s*\(\s*{escaped_var_name}\s*,')

                        btoa_matches = btoa_pattern.findall(relevant_lines)
                        has_xor_var = bool(xor_var_pattern.search(relevant_lines))

                        if btoa_matches and len(btoa_matches) == 1 and not has_xor_var:
                            last_resolved = f'singlebtoa({last_resolved})'

        return last_resolved

    @staticmethod
    def parse_assigments(code):

            ast = esprima.parseScript(code, loc=True, jsx=True)

            stringify_calls = []

            def traverse_node(node):
                if isinstance(node, dict):
                    if node.get('type') == 'CallExpression':
                        callee = node.get('callee', {})
                        if (callee.get('type') == 'MemberExpression' and
                            callee.get('object', {}).get('name') == 'JSON' and
                            callee.get('property', {}).get('name') == 'stringify' and
                            node.get('arguments') and
                            node['arguments'][0]['type'] == 'Identifier'):
                            stringify_calls.append(node['arguments'][0]['name'])
                    for v in node.values():
                        traverse_node(v)
                elif isinstance(node, list):
                    for item in node:
                        traverse_node(item)

            traverse_node(ast.toDict())

            last_stringify_arg = stringify_calls[-1] if stringify_calls else None

            if not last_stringify_arg:
                return {}

            var_values = {}

            def traverse_vars(node):
                if isinstance(node, dict):
                    if node.get('type') == 'VariableDeclarator':
                        id_node = node.get('id', {})
                        init_node = node.get('init', {})
                        if (id_node.get('type') == 'Identifier' and
                            init_node and init_node.get('type') in ('Literal', 'NumericLiteral', 'StringLiteral')):
                            var_values[id_node['name']] = init_node.get('value')
                    for v in node.values():
                        traverse_vars(v)
                elif isinstance(node, list):
                    for item in node:
                        traverse_vars(item)

            traverse_vars(ast.toDict())

            assignments = {}

            def traverse_assignments(node):
                if isinstance(node, dict):
                    if node.get('type') == 'AssignmentExpression':
                        left = node.get('left', {})
                        right = node.get('right', {})
                        if (left.get('type') == 'MemberExpression' and
                            left.get('object', {}).get('type') == 'Identifier' and
                            left.get('object', {}).get('name') == last_stringify_arg and
                            left.get('property', {}).get('type') == 'Identifier' and
                            right.get('type') == 'Identifier' and
                            node.get('loc')):
                            key_var = left['property']['name']
                            value = right['name']
                            key = var_values.get(key_var, key_var)
                            resolved_value = Parser.find_var_definition(value, node['loc']['start']['line'], code) or value
                            assignments[key] = resolved_value
                    for v in node.values():
                        traverse_assignments(v)
                elif isinstance(node, list):
                    for item in node:
                        traverse_assignments(item)

            traverse_assignments(ast.toDict())

            return assignments
    @staticmethod
    def get_xor_key(js_code: str):
        
        parsed = esprima.parseScript(js_code, tolerant=True)
        
        last_xor_call = None
        second_arg_node = None

        for node in parsed.body:
            if node.type == 'VariableDeclaration':
                for decl in node.declarations:
                    if decl.init and decl.init.type == 'CallExpression':
                        call = decl.init
                        if call.callee.type == 'Identifier' and call.callee.name == 'XOR_STR':
                            last_xor_call = call
                            second_arg_node = call.arguments[1]

        if not last_xor_call:
            return None

        if second_arg_node.type == 'Identifier':
            var_name = second_arg_node.name
        elif second_arg_node.type == 'Literal':
            return second_arg_node.value
        else:
            return None

        def find_value(nodes, name):
            for node in nodes:
                if node.type == 'VariableDeclaration':
                    for decl in node.declarations:
                        if decl.id.name == name and decl.init.type == 'Literal':
                            return decl.init.value
                elif node.type == 'ExpressionStatement' and node.expression.type == 'AssignmentExpression':
                    expr = node.expression
                    if expr.left.type == 'Identifier' and expr.left.name == name and expr.right.type == 'Literal':
                        return expr.right.value
            return None

        return find_value(parsed.body, var_name)
    
    @staticmethod
    def parse_keys(decompiled_code: str) -> tuple[str, dict]:
        
        assignments: dict = Parser.parse_assigments(decompiled_code)
        xor_key: str = Parser.get_xor_key(decompiled_code)
        
        parsed_keys: dict = {}
        randomindex = 1
        for key, value in assignments.items():
            key = str(key)
            if value.startswith("Array") and "location" not in value:
                numbers = value.split(') : ')[1].split(" + ")
                num1 = float(numbers[0])
                num2 = float(numbers[1])
                parsed_keys[key] = str(float(num1 + num2))
            elif "location" in value:
                parsed_keys[key] = "location"
            elif "cfIpLongitude" in value:
                parsed_keys[key] = "ipinfo"
            elif "maxTouchPoints" in value:
                parsed_keys[key] = "vendor"
            elif "history" in value:
                parsed_keys[key] = "history"
            elif 'window["Object"]["keys"]' in value:
                parsed_keys[key] = "localstorage"
            elif 'createElement' in value:
                parsed_keys[key] = "element"
            elif value.isdigit():
                parsed_keys[key] = value
            elif "random" in value:
                parsed_keys[key] = "random_" + str(randomindex)
                randomindex += 1
            elif "doublexor" in value:
                parsed_keys[key] = value
            elif "singlebtoa" in value:
                parsed_keys[key] = value

        return xor_key, parsed_keys
    
# NOTE dont mind this please i converted my babel parser from JS to py using AI i know its shit but i didnt wanna exec js code or smt