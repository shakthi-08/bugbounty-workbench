from .collection_view import CollectionView


class AssetsView(CollectionView):
    def __init__(self, parent=None):
        super().__init__(
            "Assets",
            "Discovered assets recorded for the selected project.",
            [("Asset", "value"), ("Type", "asset_type"), ("Source", "source"), ("HTTP", "http_status")],
            "No assets have been recorded for this project yet.",
            parent,
        )
