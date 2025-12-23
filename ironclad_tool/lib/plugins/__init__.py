import importlib
import pkgutil
import sys

class PluginManager:
    @staticmethod
    def run_all(context):
        package = sys.modules[__name__]
        for _, name, _ in pkgutil.iter_modules(package.__path__):
            try:
                module = importlib.import_module(f".{name}", package.__name__)
                if hasattr(module, "audit"):
                    module.audit(context)
            except Exception as e:
                context.register_finding("PLUGIN_ERR", "CORE", "INFO", f"Plugin '{name}' failed: {str(e)}", "")
