from .collection_view import CollectionView


class ScopesView(CollectionView):
    def __init__(self, parent=None):
        super().__init__(
            "Scopes",
            "Included and excluded targets for the selected project.",
            [("Target", "value"), ("Type", "scope_type"), ("Status", "included")],
            "No scope entries exist for this project.",
            parent,
        )
