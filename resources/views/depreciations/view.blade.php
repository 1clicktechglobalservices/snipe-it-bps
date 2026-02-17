@extends('layouts/default')

{{-- Page title --}}
@section('title')

    {{ trans('general.depreciation') }}: {{ $depreciation->name }} ({{ $depreciation->months }} {{ trans('general.months') }})

    @parent
@stop

@section('header_right')
    <i class="fa-regular fa-2x fa-square-caret-right pull-right" id="expand-info-panel-button" data-tooltip="true" title="{{ trans('button.show_hide_info') }}"></i>
@endsection

{{-- Page content --}}
@section('content')
    <x-container columns="2">
        <x-page-column class="col-md-9 main-panel">
            <x-tabs>
                <x-slot:tabnav>
                    @can('view', \App\Models\Asset::class)
                        <x-tabs.nav-item
                                class="active"
                                name="assets"
                                icon_type="asset"
                                label="{{ trans('general.assets') }}"
                                count="{{ $depreciation->assets()->AssetsForShow()->count() }}"
                                tooltip="{{ trans('general.assets') }}"
                        />
                    @endcan

                    @can('view', \App\Models\License::class)
                        <x-tabs.nav-item
                                name="licenses"
                                icon_type="licenses"
                                label="{{ trans('general.licenses') }}"
                                count="{{ $depreciation->licenses()->count() }}"
                                tooltip="{{ trans('general.licenses') }}"
                        />
                    @endcan

                    @can('view', \App\Models\AssetModel::class)
                        <x-tabs.nav-item
                                name="models"
                                icon="fa-solid fa-boxes-packing"
                                label="{{ trans('general.asset_models') }}"
                                count="{{ $depreciation->models_count }}"
                                tooltip="{{ trans('general.asset_models') }}"
                        />
                    @endcan

                </x-slot:tabnav>

                <x-slot:tabpanes>

                    <!-- start assets tab pane -->
                    @can('view', \App\Models\Asset::class)
                        <x-tabs.pane name="assets" class="in active">
                            <x-slot:header>
                                {{ trans('general.assets') }}
                            </x-slot:header>

                            <x-slot:bulkactions>
                                <x-table.bulk-assets />
                            </x-slot:bulkactions>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        show_advanced_search="true"
                                        buttons="assetButtons"
                                        api_url="{{ route('api.assets.index', ['depreciation_id' => $depreciation->id]) }}"
                                        :presenter="\App\Presenters\AssetPresenter::dataTableLayout()"
                                        export_filename="export-depreciation-{{ str_slug($depreciation->name) }}-assets-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                        <!-- end assets tab pane -->
                    @endcan


                    <!-- start licenses tab pane -->
                    @can('view', \App\Models\License::class)
                        <x-tabs.pane name="licenses">
                            <x-slot:header>
                                {{ trans('general.licenses') }}
                            </x-slot:header>
                            <x-slot:content>
                                <x-table
                                        name="licenses"
                                        buttons="licenseButtons"
                                        api_url="{{ route('api.licenses.index', ['depreciation_id' => $depreciation->id]) }}"
                                        :presenter="\App\Presenters\LicensePresenter::dataTableLayout()"
                                        export_filename="export-depreciation-{{ str_slug($depreciation->name) }}-licences-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end licenses tab pane -->

                    <!-- start models tab pane -->
                    @can('view', \App\Models\AssetModel::class)
                        <x-tabs.pane name="models">
                            <x-slot:header>
                                {{ trans('general.models') }}
                            </x-slot:header>
                            <x-slot:content>
                                <x-table
                                        name="models"
                                        buttons="modelButtons"
                                        api_url="{{ route('api.models.index', ['depreciation_id' => $depreciation->id]) }}"
                                        :presenter="\App\Presenters\AssetModelPresenter::dataTableLayout()"
                                        export_filename="export-depreciation-{{ str_slug($depreciation->name) }}-models-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end licenses tab pane -->



                </x-slot:tabpanes>

            </x-tabs>



        </x-page-column>
        <x-page-column class="col-md-3">
            <x-box>
                <x-box.info-panel :infoPanelObj="$depreciation">

                    <x-slot:before_list>

                        @can('update', $depreciation)
                            @if ($depreciation->deleted_at=='')
                                <a href="{{ route('depreciations.edit', ['depreciation' => $depreciation->id]) }}" class="btn btn-block btn-sm btn-warning btn-social">
                                    <x-icon type="edit" />
                                    {{ trans('general.update') }}
                                </a>
                            @else
                                <a class="btn btn-block btn-sm btn-warning btn-social disabled">
                                    <x-icon type="edit" />
                                    {{ trans('general.update') }}
                                </a>
                            @endif
                        @endcan

                            @can('delete', $depreciation)

                                @if ($depreciation->deleted_at=='')
                                    @if ($depreciation->isDeletable())
                                        <button class="btn btn-sm btn-block btn-danger btn-social delete-asset" data-toggle="modal" data-title="{{ trans('general.delete') }}" data-content="{{ trans('general.sure_to_delete_var', ['item' => $depreciation->name]) }}" data-target="#dataConfirmModal">
                                            <x-icon type="delete" /> {{ trans('general.delete') }}
                                        </button>
                                    @else
                                        <div data-placement="top" data-tooltip="true" data-title="{{ trans('general.cannot_be_deleted') }}" style="padding-top: 5px; padding-bottom: 5px;">
                                            <a href="#" class="btn btn-block btn-sm btn-danger btn-social hidden-print disabled" data-tooltip="true">
                                                <x-icon type="delete" /> {{ trans('general.delete') }}
                                            </a>
                                        </div>
                                    @endif

                                @endif

                            @endcan

                    </x-slot:before_list>
                </x-box.info-panel>
            </x-box>

        </x-page-column>

    </x-container>

@stop

@section('moar_scripts')
    @include ('partials.bootstrap-table')

@stop
